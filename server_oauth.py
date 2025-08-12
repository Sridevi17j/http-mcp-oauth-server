"""
OAuth-protected MCP Server for Web Content Extraction
Using Auth0 JWT validation
"""

import os
import json
import jwt
import requests
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('env')

# Initialize FastMCP server with streamable HTTP
mcp = FastMCP(name="web-content-extractor")

class Auth0TokenValidator:
    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN")
        self.audience = os.environ.get("AUTH0_AUDIENCE")
        self.algorithms = ["RS256"]
        self.jwks_uri = f"https://{self.domain}/.well-known/jwks.json"
        self._jwks_cache = None
    
    def get_jwks(self):
        """Get JWKS from Auth0"""
        if self._jwks_cache is None:
            try:
                response = requests.get(self.jwks_uri, timeout=10)
                response.raise_for_status()
                self._jwks_cache = response.json()
            except Exception as e:
                print(f"Failed to get JWKS: {e}")
                return None
        return self._jwks_cache
    
    def get_signing_key(self, kid):
        """Get signing key for token verification"""
        jwks = self.get_jwks()
        if not jwks:
            return None
            
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        return None
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate Auth0 JWT token"""
        try:
            # Decode token header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                print("No kid in token header")
                return None
            
            # Get signing key
            signing_key = self.get_signing_key(kid)
            if not signing_key:
                print(f"Could not find signing key for kid: {kid}")
                return None
            
            # Verify token
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=f"https://{self.domain}/"
            )
            
            print(f"Token validated for user: {payload.get('sub')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            print("Token has expired")
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
        except Exception as e:
            print(f"Token validation error: {e}")
        
        return None

# Initialize Auth0 validator
auth_validator = Auth0TokenValidator()

def extract_web_content_logic(url: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Core web content extraction logic with user context"""
    try:
        print(f"User {user_info.get('sub')} extracting content from: {url}")
        
        # Validate URL
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        # Fetch the webpage
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML content
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract title
        title_tag = soup.find('title')
        title = title_tag.get_text().strip() if title_tag else ""
        
        # Extract meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        meta_description = meta_desc.get('content', '') if meta_desc else ''
        
        # Remove unwanted elements for cleaner text
        for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
            element.decompose()
        
        # Extract main text content
        body = soup.find('body')
        if body:
            text_content = ' '.join(body.get_text().split())
        else:
            text_content = ' '.join(soup.get_text().split())
        
        # Extract links
        links = []
        for a_tag in soup.find_all('a', href=True)[:10]:  # Limit to 10 links
            href = a_tag.get('href')
            text = a_tag.get_text().strip()
            if href and text:
                absolute_url = urljoin(url, href)
                links.append({
                    "href": absolute_url,
                    "text": text
                })
        
        # Prepare structured response
        result = {
            "operation": "web_content_extraction",
            "url": url,
            "title": title,
            "meta_description": meta_description,
            "text_content": text_content[:2000],  # Limit to 2000 chars
            "links": links,
            "content_length": len(text_content),
            "extracted_at": datetime.now().isoformat(),
            "user": user_info.get('sub'),
            "success": True
        }
        
        print(f"Successfully extracted content from {url} for user {user_info.get('sub')}")
        return result
        
    except Exception as error:
        error_result = {
            "operation": "web_content_extraction",
            "url": url,
            "error": str(error),
            "extracted_at": datetime.now().isoformat(),
            "user": user_info.get('sub'),
            "success": False
        }
        print(f"Error extracting content from {url}: {error}")
        return error_result

# MCP tool with OAuth protection
@mcp.tool(
    name="extract_web_content_oauth",
    description="Extract web content with OAuth authentication",
    structured_output=True,
)
def extract_web_content_oauth(url: str, access_token: str = None) -> Dict[str, Any]:
    """
    Extract web content with OAuth authentication.
    
    Args:
        url: The URL of the webpage to extract content from
        access_token: Auth0 JWT access token
        
    Returns:
        Structured dictionary containing extracted content and user info
    """
    # Check if access token is provided
    if not access_token:
        return {
            "operation": "web_content_extraction",
            "url": url,
            "error": "Missing access token - OAuth authentication required",
            "extracted_at": datetime.now().isoformat(),
            "success": False
        }
    
    # Validate access token
    user_info = auth_validator.validate_token(access_token)
    if not user_info:
        return {
            "operation": "web_content_extraction",
            "url": url,
            "error": "Invalid or expired access token",
            "extracted_at": datetime.now().isoformat(),
            "success": False
        }
    
    # Extract content with user context
    return extract_web_content_logic(url, user_info)

# Simple tool without OAuth for testing
@mcp.tool(
    name="extract_web_content",
    description="Extract web content without OAuth (for testing)",
    structured_output=True,
)
def extract_web_content(url: str) -> Dict[str, Any]:
    """Extract web content without OAuth"""
    fake_user = {"sub": "anonymous"}
    return extract_web_content_logic(url, fake_user)

@mcp.tool(
    name="validate_token",
    description="Validate Auth0 JWT token",
    structured_output=True,
)
def validate_token(access_token: str) -> Dict[str, Any]:
    """
    Validate an Auth0 JWT token.
    
    Args:
        access_token: Auth0 JWT access token
        
    Returns:
        Token validation result with user information
    """
    user_info = auth_validator.validate_token(access_token)
    
    if user_info:
        return {
            "operation": "token_validation",
            "valid": True,
            "user_id": user_info.get('sub'),
            "audience": user_info.get('aud'),
            "issued_at": user_info.get('iat'),
            "expires_at": user_info.get('exp'),
            "validated_at": datetime.now().isoformat(),
            "success": True
        }
    else:
        return {
            "operation": "token_validation",
            "valid": False,
            "error": "Invalid or expired token",
            "validated_at": datetime.now().isoformat(),
            "success": False
        }

if __name__ == "__main__":
    print("Starting OAuth-protected MCP Server for Web Content Extraction")
    print("Server will be available at: http://localhost:8000/mcp")
    print("Available tools:")
    print("  - extract_web_content_oauth: OAuth-protected content extraction")
    print("  - extract_web_content: Non-protected content extraction (testing)")
    print("  - validate_token: Validate Auth0 JWT tokens")
    print("Starting with streamable-http transport...")
    
    mcp.run(transport="streamable-http")