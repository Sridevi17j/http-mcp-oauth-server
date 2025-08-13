"""
Run from the repository root:
    uv run web_extraction_server.py
"""
from fastmcp import FastMCP
import requests
from bs4 import BeautifulSoup
import os

# Stateful server (maintains session state)
mcp = FastMCP("WebExtractionServer")

@mcp.tool()
def extract_web_text(url: str) -> str:
    """Extract text content from a web page URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.get_text(strip=True)
    except requests.RequestException as e:
        return f"Error fetching URL: {str(e)}"
    except Exception as e:
        return f"Error extracting text: {str(e)}"

# Run server with streamable_http transport
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    
    print(f"Starting server on 0.0.0.0:{port}")
    
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)