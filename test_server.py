from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl
import os

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-xrlojx8grz2bwyup.us.auth0.com")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-web-extractor")
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "https://your-render-url.onrender.com")

# OAuth endpoints
OAUTH_ISSUER = f"https://{AUTH0_DOMAIN}/"
JWKS_URI = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

# Configure token validation for your identity provider
token_verifier = JWTVerifier(
    jwks_uri=JWKS_URI,
    issuer=OAUTH_ISSUER,
    audience="mcp-web-extractor"
)

# Create the remote auth provider
auth = RemoteAuthProvider(
    token_verifier=token_verifier,
    authorization_servers=[AnyHttpUrl("https://dev-xrlojx8grz2bwyup.us.auth0.com")],
    resource_server_url="https://http-mcp-oauth-server-2.onrender.com"
)

mcp = FastMCP(name="Company API", auth=auth)

@mcp.tool
def test_str(name: str) -> str:
    return f"Hello, {name}!"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))

    # Start an HTTP server on port 8000
    mcp.run(transport="http", host="0.0.0.0", port=8000)