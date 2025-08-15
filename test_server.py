"""  
    MCP OAuth Server Example  
  
This module demonstrates a FastMCP server with Bearer token authentication mounted on FastAPI,  
including OAuth 2.1 endpoints for dynamic client registration and metadata discovery.  
"""  
  
import time  
from fastapi.responses import JSONResponse  
import os  
  
from fastapi import FastAPI, HTTPException, Request  
from fastmcp import FastMCP  
from fastmcp.server.auth import BearerAuthProvider  
#from loguru import logger  
from starlette.responses import PlainTextResponse  
from fastapi.middleware.cors import CORSMiddleware  
from datetime import datetime  
import dotenv  
  
dotenv.load_dotenv()  
  
# Configuration - use environment variables or defaults  
ISSUER = os.getenv("CLERK_ISSUER", "https://tidy-wren-43.clerk.accounts.dev")  
AUDIENCE = os.getenv("CLERK_AUDIENCE", "3MjfL6Ioir3mViNC")  
CLIENT_SECRET = os.getenv("CLERK_CLIENT_SECRET","0sPPxTdU1IZf8BOBlAuTokthO4cR54z1")  
BASE_URL = os.getenv("BASE_URL", "https://http-mcp-oauth-server-2.onrender.com")  

print("ISSUER:", ISSUER)
print("AUDIENCE:", AUDIENCE)
print("CLIENT_SECRET:", CLIENT_SECRET)
print("BASE_URL:", BASE_URL)
  
#logger.info(f"ISSUER: {ISSUER}")  
#logger.info(f"AUDIENCE: {AUDIENCE}")  
#logger.info(f"CLIENT_SECRET: {CLIENT_SECRET}")  
#logger.info(f"BASE_URL: {BASE_URL}")  
  
  
def mcp_factory() -> FastMCP:  
    """Create and configure the FastMCP server."""  
    #logger.info("Initializing MCP server")  
  
    auth = BearerAuthProvider(  
        jwks_uri=f"{ISSUER}/.well-known/jwks.json",  
        issuer=ISSUER,  
        audience=AUDIENCE,  
    )  
  
    mcp = FastMCP(name="MCP OAuth Server", auth=auth)  
  
    @mcp.custom_route("/health", methods=["GET"])  
    def health_check(request: Request) -> PlainTextResponse:  
        return PlainTextResponse("OK", status_code=200)  
  
    # Example tool that requires authentication  
    @mcp.tool  
    def hello(name: str) -> str:  
        """A protected greeting tool."""  
        return f"Hello, {name}! This is a protected endpoint."  
  
    @mcp.tool  
    def add_numbers(a: int, b: int) -> int:  
        """Add two numbers together."""  
        return a + b  
  
    #logger.debug("Tools registered with MCP server")  
    return mcp  
  
  
def create_app(transport: str = "http") -> FastAPI:  # Changed default to "http"  
    """Create the FastAPI application with mounted MCP server."""  
    # Initialize MCP server  
    mcp: FastMCP = mcp_factory()  
  
    # Create the MCP app with specified transport  
    mcp_app = mcp.http_app(path="/mcp", transport=transport)  
  
    # Create a FastAPI app that mounts the MCP app  
    app = FastAPI(  
        title="MCP OAuth Server Example",  
        description="FastMCP server with Bearer token authentication and OAuth endpoints",  
        version=datetime.now().strftime("%Y-%m-%d"),  
        debug=True,  
        lifespan=mcp_app.lifespan,  
    )  
  
    app.add_middleware(  
        CORSMiddleware,  
        allow_origins=["*"],  
        allow_credentials=True,  
        allow_methods=["*"],  
        allow_headers=["*"],  
    )  
  
    # OAuth 2.1 Authorization Server Metadata endpoint  
    @app.get("/.well-known/oauth-authorization-server")  
    def oauth_metadata() -> JSONResponse:  
        """OAuth 2.1 Authorization Server Metadata."""  
        return JSONResponse(  
            {  
                "issuer": ISSUER,  
                "authorization_endpoint": f"{ISSUER}/oauth/authorize",  
                "token_endpoint": f"{ISSUER}/oauth/token",  
                "jwks_uri": f"{ISSUER}/.well-known/jwks.json",  
                "registration_endpoint": f"{ISSUER}/oauth/register",  
                # "registration_endpoint": f"{BASE_URL}/register",  
                "response_types_supported": ["code"],  
                "code_challenge_methods_supported": ["S256"],  
                "token_endpoint_auth_methods_supported": ["client_secret_post"],  
                "grant_types_supported": ["authorization_code", "refresh_token"],  
            }  
        )  
  
    # OpenID Connect Discovery endpoint  
    @app.get("/.well-known/openid-configuration")  
    async def openid_config():  
        """OpenID Connect Discovery endpoint."""  
        # In a real implementation, you might proxy to an actual OIDC provider  
        return JSONResponse(  
            {  
                "issuer": ISSUER,  
                "authorization_endpoint": f"{ISSUER}/oauth/authorize",  
                "token_endpoint": f"{ISSUER}/oauth/token",  
                "jwks_uri": f"{ISSUER}/.well-known/jwks.json",  
                "response_types_supported": ["code"],  
                "subject_types_supported": ["public"],  
                "id_token_signing_alg_values_supported": ["RS256"],  
            }  
        )  
  
    # OAuth Protected Resource Metadata  
    @app.get("/.well-known/oauth-protected-resource")  
    def oauth_protected_resource():  
        """OAuth 2.1 Protected Resource Metadata."""  
        return JSONResponse(  
            {  
                "resource": BASE_URL,  
                "authorization_servers": [ISSUER],  
                "jwks_uri": f"{ISSUER}/.well-known/jwks.json",  
                "bearer_methods_supported": ["header"],  
                "resource_documentation": f"{BASE_URL}/docs",  
            }  
        )  
  
    # Dynamic Client Registration endpoint  
    @app.post("/register")  
    async def register(request: Request):  
        """OAuth 2.1 Dynamic Client Registration endpoint."""  
        #logger.info(f"/register headers: {dict(request.headers)}")  
        raw_body = await request.body()  
        #logger.info(f"/register raw body: {raw_body}")  
  
        try:  
            data = await request.json()  
            #logger.info(f"/register parsed data: {data}")  
        except Exception as e:  
            #logger.error(f"Failed to parse JSON body: {e}")  
            return JSONResponse(  
                {"error": "Invalid JSON body", "details": str(e)}, status_code=400  
            )  
  
        # Generate client credentials  
        client_id = AUDIENCE  
        client_secret = CLIENT_SECRET  
        now = int(time.time())  
  
        # Build the response according to OAuth 2.0 Dynamic Client Registration spec  
        response_data = {  
            "client_id": client_id,  
            "client_secret": client_secret,  
            "client_id_issued_at": now,  
            "client_secret_expires_at": 0,  # 0 means no expiration  
            "redirect_uris": data.get("redirect_uris", []),  
            "token_endpoint_auth_method": data.get(  
                "token_endpoint_auth_method", "client_secret_post"  
            ),  
            "grant_types": data.get("grant_types", ["authorization_code"]),  
            "response_types": data.get("response_types", ["code"]),  
            "client_name": data.get("client_name", ""),  
            "scope": data.get("scope", ""),  
        }  
  
        #logger.info(f"/register response: {response_data}")  
        return JSONResponse(response_data, status_code=201)  
  
    # Development token endpoint  
    @app.get("/dev/token")  
    def get_dev_token():  
        """Generate a development token for testing."""  
        if hasattr(mcp, "_key_pair"):  
            token = mcp._key_pair.create_token(  
                subject="dev-user",  
                issuer=ISSUER,  
                audience=AUDIENCE,  
                scopes=["read", "write"],  
            )  
            return JSONResponse(  
                {  
                    "access_token": token,  
                    "token_type": "Bearer",  
                    "expires_in": 3600,  
                    "scope": "read write",  
                }  
            )  
        else:  
            raise HTTPException(status_code=500, detail="Key pair not available")  
  
    # Mount the MCP app (after all other routes)  
    app.mount("/mcp", mcp_app)  
    #logger.debug("MCP server mounted at /mcp")  
  
    return app  
  
  
def main(  
    transport: str = "http",  # Changed default from "sse" to "http"  
    host: str = "127.0.0.1",  
    port: int = 8000,  
    log_level: str = "info",  
):  
    """Run the server."""  
    import uvicorn  
  
    # Initialize FastAPI + MCP app  
    app = create_app(transport)  
  
    # Print development token for convenience  
    #logger.info(  f"Starting MCP OAuth Server [transport={transport}, host={host}, port={port}]"  )  
    #logger.info(f"Server will be available at: http://{host}:{port}")  
    #logger.info(f"MCP endpoint: http://{host}:{port}/mcp")  
    #logger.info(f"Development token endpoint: http://{host}:{port}/dev/token")  
    #logger.info(  f"OAuth metadata: http://{host}:{port}/.well-known/oauth-authorization-server"  )  
  
    # Start the server  
    uvicorn.run(app, log_level=log_level, host=host, port=port)  
  
  
if __name__ == "__main__":  
    import argparse  
  
    #logger.debug("Starting VLM Run MCP server")  
    parser = argparse.ArgumentParser()  
    parser.add_argument("--transport", type=str, default="http")  # Changed default  
    parser.add_argument("--host", type=str, default="0.0.0.0")  
    parser.add_argument("--port", type=int, default=8000)  
    parser.add_argument("--log-level", type=str, default="debug")  
    args = parser.parse_args()  
    main(args.transport, args.host, args.port, args.log_level)