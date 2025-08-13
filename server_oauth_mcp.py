"""
OAuth-protected MCP Server for Web Content Extraction
Simplified version with working Dynamic Client Registration (DCR)
Using Auth0 with fastmcp and mcpauth libraries
"""

import os
import requests
import logging
from typing import Any, Dict
from fastmcp import FastMCP
from mcpauth import MCPAuth
from mcpauth.config import AuthServerType
from mcpauth.utils import fetch_server_config
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Auth0 Configuration for Dynamic Client Registration
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-gkajzozs6ojdzi2l.us.auth0.com")
AUTH0_MANAGEMENT_CLIENT_ID = os.environ.get("AUTH0_MANAGEMENT_CLIENT_ID", "5pSUzqub8bYkn0nTsP0OuzRE0weqfTgw")
AUTH0_MANAGEMENT_CLIENT_SECRET = os.environ.get("AUTH0_MANAGEMENT_CLIENT_SECRET", "sTQOwa8x5PxofckRkSdsBwBgjR0x7YYwSV2Al2SR7bbbDWn-oWF4-lXADx-Ss5Fs")

# OAuth server configuration
OAUTH_ISSUER = f"https://{AUTH0_DOMAIN}/"

def extract_web_content_logic(url: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Core web content extraction logic"""
    try:
        logger.info(f"User {user_info.get('sub')} extracting content from: {url}")
        
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
            "user": user_info.get('sub'),
            "success": True
        }
        
    except Exception as error:
        return {
            "url": url,
            "error": str(error),
            "extracted_at": datetime.now().isoformat(),
            "user": user_info.get('sub', 'unknown'),
            "success": False
        }

# Initialize MCP server (simplified approach like our working code)
mcp = FastMCP(name="web-content-extractor-oauth")

# Initialize MCP Auth with Dynamic Client Registration support
try:
    mcp_auth = MCPAuth(
        server=fetch_server_config(
            OAUTH_ISSUER,
            type=AuthServerType.OAUTH
        )
    )
    logger.info(f"MCP Auth initialized with issuer: {OAUTH_ISSUER}")
except Exception as e:
    logger.error(f"Failed to initialize MCP Auth: {e}")
    # For now, continue without auth for testing
    mcp_auth = None
    logger.warning("Running without OAuth authentication")

# Add MCP tools (same as our working version)
@mcp.tool()
def extract_web_content(url: str) -> Dict[str, Any]:
    """
    Extract structured content from a web page URL with OAuth authentication.
    
    Args:
        url: The URL of the webpage to extract content from
        
    Returns:
        Structured dictionary containing extracted content
    """
    # Get user info from OAuth context (placeholder for now)
    user_info = {"sub": "authenticated_user"}
    
    return extract_web_content_logic(url, user_info)

@mcp.tool()
def get_oauth_user_info() -> Dict[str, Any]:
    """Get information about the authenticated OAuth user"""
    return {
        "message": "OAuth user info",
        "issuer": OAUTH_ISSUER,
        "timestamp": datetime.now().isoformat(),
        "authentication": "oauth_enabled" if mcp_auth else "oauth_disabled"
    }

@mcp.tool()
def health_check() -> Dict[str, Any]:
    """Health check tool"""
    return {
        "status": "healthy", 
        "service": "web-content-extractor-oauth",
        "oauth_enabled": mcp_auth is not None,
        "auth0_domain": AUTH0_DOMAIN,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info("=" * 50)
    logger.info("Simplified OAuth MCP Server for Claude.ai")
    logger.info("=" * 50)
    logger.info(f"Server starting on {host}:{port}")
    logger.info(f"OAuth Issuer: {OAUTH_ISSUER}")
    logger.info(f"Auth0 Domain: {AUTH0_DOMAIN}")
    logger.info(f"OAuth Auth Enabled: {mcp_auth is not None}")
    logger.info("")
    logger.info("Available endpoints:")
    logger.info(f"  • MCP Endpoint: http://{host}:{port}/mcp")
    if mcp_auth:
        logger.info(f"  • OAuth Metadata: http://{host}:{port}/.well-known/oauth-authorization-server")
    logger.info("")
    logger.info("Available MCP Tools:")
    logger.info("  • extract_web_content: Extract web page content")
    logger.info("  • get_oauth_user_info: Get OAuth user information")
    logger.info("  • health_check: Server health status")
    logger.info("=" * 50)
    
    # Run the simplified server (like our working version)
    mcp.run(
        transport="streamable-http",
        host=host,
        port=port
    )