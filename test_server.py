from fastapi import dependencies
from fastmcp import FastMCP
#from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.auth import RemoteAuthProvider

from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl
import os
import sys
from datetime import datetime
import logging  
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("fastmcp.server.auth.providers.jwt").setLevel(logging.DEBUG)
from fastapi.middleware.cors import CORSMiddleware


from server_oauth_mcp import AUTH0_AUDIENCE



#AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-xrlojx8grz2bwyup.us.auth0.com")
#AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-web-extractor")
#AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-content-api")
#RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "https://http-mcp-oauth-server-2.onrender.com")

# OAuth endpoints
#OAUTH_ISSUER = f"https://{AUTH0_DOMAIN}/"
#JWKS_URI = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

# Configure token validation for your identity provider
token_verifier = JWTVerifier(
    jwks_uri="https://dev-xrlojx8grz2bwyup.us.auth0.com/.well-known/jwks.json",
    issuer="https://dev-xrlojx8grz2bwyup.us.auth0.com/",
    #issuer=None,
    audience="https://mcp-content-api"
    #audience=None
)

# Create the remote auth provider
auth = RemoteAuthProvider(
    token_verifier=token_verifier,
    authorization_servers=[AnyHttpUrl("https://dev-xrlojx8grz2bwyup.us.auth0.com")],
    resource_server_url="https://http-mcp-oauth-server-2.onrender.com/mcp"
)

mcp = FastMCP(name="Company API", auth=auth)

#@mcp.tool
#def test_str(name: str) -> str:
#    print(f"Tool called at: {datetime.now()}", file=sys.stderr)

#    return f"Hello, {name}!"

@mcp.tool  
def test_str(name: str) -> str:  
    print(f"✅ Tool called successfully at: {datetime.now()}", file=sys.stderr)  
    print(f"✅ Request reached server!", file=sys.stderr)  
    return f"Hello, {name}!"

app = mcp.streamable_http_app()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # or lock to the Inspector origin you use
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))

    # Start an HTTP server on port 8000
    mcp.run(transport="http", host="0.0.0.0", port=8000)