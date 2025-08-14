"""
OAuth-protected MCP Server for Web Content Extraction
Proper implementation using FastMCP RemoteAuthProvider and JWTVerifier
Following official FastMCP OAuth documentation
"""

import os
import requests
import logging
from typing import Any, Dict
from fastmcp import FastMCP
from fastmcp.server.auth.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dotenv import load_dotenv
from pydantic import AnyHttpUrl

# Load environment variables
load_dotenv('.env')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Auth0 Configuration
#AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-gkajzozs6ojdzi2l.us.auth0.com")
#AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-server/api")  # You may need to set this
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-xrlojx8grz2bwyup.us.auth0.com")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-web-extractor")
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "https://your-render-url.onrender.com")

# OAuth endpoints
OAUTH_ISSUER = f"https://{AUTH0_DOMAIN}/"
JWKS_URI = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

def extract_web_content_logic(url: str, user_info: Dict[str, Any] = None) -> Dict[str, Any]:
    """Core web content extraction logic"""
    try:
        user_id = user_info.get('sub', 'authenticated_user') if user_info else 'anonymous'
        logger.info(f"User {user_id} extracting content from: {url}")
        
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
        
        # Remove unwanted elements
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
        for a_tag in soup.find_all('a', href=True)[:10]:
            href = a_tag.get('href')
            text = a_tag.get_text().strip()
            if href and text:
                absolute_url = urljoin(url, href)
                links.append({
                    "href": absolute_url,
                    "text": text
                })
        
        return {
            "url": url,
            "title": title,
            "meta_description": meta_description,
            "text_content": text_content[:2000],  # Limit to 2000 chars
            "links": links,
            "content_length": len(text_content),
            "extracted_at": datetime.now().isoformat(),
            "user": user_id,
            "success": True
        }
        
    except Exception as error:
        return {
            "url": url,
            "error": str(error),
            "extracted_at": datetime.now().isoformat(),
            "user": user_info.get('sub', 'unknown') if user_info else 'unknown',
            "success": False
        }

# Configure JWT token verification for Auth0
try:
    token_verifier = JWTVerifier(
        jwks_uri=JWKS_URI,
        issuer=OAUTH_ISSUER,
        audience=AUTH0_AUDIENCE
    )
    logger.info(f"JWT Verifier configured for issuer: {OAUTH_ISSUER}")
except Exception as e:
    logger.error(f"Failed to configure JWT verifier: {e}")
    token_verifier = None

# Create Remote Auth Provider following FastMCP pattern
if token_verifier:
    try:
        auth_provider = RemoteAuthProvider(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(OAUTH_ISSUER)],
            resource_server_url=RESOURCE_SERVER_URL
        )
        logger.info("RemoteAuthProvider configured successfully")
    except Exception as e:
        logger.error(f"Failed to configure RemoteAuthProvider: {e}")
        auth_provider = None
else:
    auth_provider = None

# Create FastMCP server with proper OAuth authentication
if auth_provider:
    mcp = FastMCP(name="web-content-extractor-oauth", auth=auth_provider)
    logger.info("MCP server created with OAuth authentication")
else:
    mcp = FastMCP(name="web-content-extractor-oauth")
    logger.warning("MCP server created WITHOUT OAuth authentication (fallback mode)")

# MCP Tools with proper OAuth integration
@mcp.tool()
def extract_web_content(url: str) -> Dict[str, Any]:
    """
    Extract structured content from a web page URL.
    Requires OAuth authentication when auth is enabled.
    
    Args:
        url: The URL of the webpage to extract content from
        
    Returns:
        Structured dictionary containing extracted content
    """
    # FastMCP will automatically inject user info when authenticated
    # For now, we'll handle both authenticated and non-authenticated cases
    return extract_web_content_logic(url)

@mcp.tool()
def get_oauth_user_info() -> Dict[str, Any]:
    """
    Get information about the current authentication status and user.
    
    Returns:
        Authentication status and user information
    """
    if auth_provider:
        return {
            "authentication_enabled": True,
            "auth_provider": "Auth0",
            "issuer": OAUTH_ISSUER,
            "audience": AUTH0_AUDIENCE,
            "jwks_uri": JWKS_URI,
            "discovery_endpoint": "/.well-known/oauth-protected-resource",
            "authorization_servers": [OAUTH_ISSUER],
            "resource_server": RESOURCE_SERVER_URL,
            "timestamp": datetime.now().isoformat(),
            "status": "oauth_required_and_configured"
        }
    else:
        return {
            "authentication_enabled": False,
            "status": "oauth_disabled_fallback_mode",
            "reason": "JWT verifier configuration failed",
            "issuer": OAUTH_ISSUER,
            "timestamp": datetime.now().isoformat()
        }

@mcp.tool()
def health_check() -> Dict[str, Any]:
    """
    Health check for the MCP server.
    
    Returns:
        Server health status and configuration
    """
    return {
        "status": "healthy", 
        "service": "web-content-extractor-oauth",
        "oauth_enabled": auth_provider is not None,
        "oauth_provider": "Auth0" if auth_provider else None,
        "auth0_domain": AUTH0_DOMAIN,
        "resource_server_url": RESOURCE_SERVER_URL,
        "discovery_endpoint": "/.well-known/oauth-protected-resource" if auth_provider else None,
        "mcp_auth_pattern": "RemoteAuthProvider + JWTVerifier",
        "timestamp": datetime.now().isoformat()
    }

@mcp.tool()
def test_authentication() -> Dict[str, Any]:
    """
    Test tool to verify authentication is working.
    This tool should only be accessible with valid OAuth token when auth is enabled.
    
    Returns:
        Authentication test results
    """
    return {
        "message": "Authentication test successful",
        "note": "If you can see this, authentication is working correctly",
        "oauth_enforced": auth_provider is not None,
        "auth_provider": "Auth0 via RemoteAuthProvider",
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info("=" * 60)
    logger.info("FastMCP OAuth Server with RemoteAuthProvider")
    logger.info("=" * 60)
    logger.info(f"Server starting on {host}:{port}")
    logger.info(f"Auth0 Domain: {AUTH0_DOMAIN}")
    logger.info(f"OAuth Issuer: {OAUTH_ISSUER}")
    logger.info(f"JWKS URI: {JWKS_URI}")
    logger.info(f"Audience: {AUTH0_AUDIENCE}")
    logger.info(f"Resource Server: {RESOURCE_SERVER_URL}")
    logger.info("")
    
    if auth_provider:
        logger.info("🔒 OAUTH AUTHENTICATION ENABLED")
        logger.info("   • Using RemoteAuthProvider + JWTVerifier")
        logger.info("   • Discovery endpoint: /.well-known/oauth-protected-resource")
        logger.info("   • Supports Dynamic Client Registration")
        logger.info("")
        logger.info("🔐 Claude.ai OAuth Flow:")
        logger.info("   1. Claude discovers /.well-known/oauth-protected-resource")
        logger.info("   2. Claude gets 401 → triggers OAuth flow")
        logger.info("   3. Claude registers with Auth0 (DCR)")
        logger.info("   4. User authenticates via Auth0")
        logger.info("   5. Claude gets JWT token")
        logger.info("   6. Tools become available")
    else:
        logger.info("⚠️  OAUTH AUTHENTICATION DISABLED")
        logger.info("   • Running in fallback mode")
        logger.info("   • Tools accessible without authentication")
        logger.info("   • Check Auth0 configuration")
    
    logger.info("")
    logger.info("Available MCP Tools:")
    logger.info("   • extract_web_content: Extract web page content")
    logger.info("   • get_oauth_user_info: OAuth status and configuration")
    logger.info("   • health_check: Server health and auth status")
    logger.info("   • test_authentication: Verify auth is working")
    logger.info("")
    logger.info("Environment Variables Needed:")
    logger.info("   • AUTH0_DOMAIN (configured)")
    logger.info("   • AUTH0_AUDIENCE (may need to be set)")
    logger.info("   • RESOURCE_SERVER_URL (may need to be set to your Render URL)")
    logger.info("=" * 60)
    
    # Run the server using FastMCP's built-in method
    mcp.run(
        transport="streamable-http",
        host=host,
        port=port
    )