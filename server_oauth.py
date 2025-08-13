"""
Run from the repository root:
    uv run web_extraction_server.py
"""
from mcp.server.fastmcp import FastMCP
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
    # Set environment variables for Render
    os.environ.setdefault("HOST", "0.0.0.0")
    if "PORT" not in os.environ:
        os.environ["PORT"] = "8000"
    
    mcp.run(transport="streamable-http")