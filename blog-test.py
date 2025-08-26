import os, sys, logging, uvicorn
from datetime import datetime
from pydantic import AnyHttpUrl
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from fastmcp import FastMCP
from fastmcp.server.auth.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token, AccessToken

logging.basicConfig(level=logging.INFO)
logging.getLogger("fastmcp.server.auth.providers.jwt").setLevel(logging.DEBUG)

#AUTH0_DOMAIN   = "dev-xrlojx8grz2bwyup.us.auth0.com"
#AUTH0_ISSUER   = f"https://{AUTH0_DOMAIN}/"
#AUTH0_AUDIENCE = "https://mcp-content-api"
#ESOURCE_SERVER_URL = "http://127.0.0.1:8000/mcp"

token_verifier = JWTVerifier(
    jwks_uri="https://dev-xrlojx8grz2bwyup.us.auth0.com/.well-known/jwks.json",
    issuer="https://dev-xrlojx8grz2bwyup.us.auth0.com/",
    audience="https://mcp-content-api",
)

auth = RemoteAuthProvider(
    token_verifier=token_verifier,
    authorization_servers=[AnyHttpUrl("https://dev-xrlojx8grz2bwyup.us.auth0.com")],
    resource_server_url="https://http-mcp-oauth-server-2.onrender.com/mcp",
)

mcp = FastMCP(name="Company API", auth=auth)

@mcp.tool
def test_str(name: str) -> str:
    print(f"✅ Tool called at: {datetime.now()}", file=sys.stderr)
    return f"Hello, {name}!"

@mcp.tool
def whoami() -> dict:
    token: AccessToken | None = get_access_token()
    if not token:
        return {"authenticated": False, "reason": "no token present"}
    claims = token.claims or {}
    scope  = claims.get("scope")
    return {
        "authenticated": True,
        "subject": claims.get("sub"),
        "audience": claims.get("aud"),
        "issuer": claims.get("iss"),
        "scopes": scope.split() if isinstance(scope, str) else scope,
        "expires_at": token.expires_at,
        "all_claims": claims,
    }

# Build the streamable app and wrap with FastAPI (so middleware applies)
asgi = mcp.streamable_http_app(path="/mcp")
app = FastAPI(lifespan=asgi.lifespan)
app.mount("/mcp", asgi)

# Optional: CORS for browser-based clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), log_level="debug")
