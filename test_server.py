from fastmcp import FastMCP  
from fastmcp.server.auth import RemoteAuthProvider  
from fastmcp.server.auth.providers.jwt import JWTVerifier  
from pydantic import AnyHttpUrl  
from starlette.routing import Route  
from starlette.responses import RedirectResponse  
import os  
import sys  
from datetime import datetime  

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-xrlojx8grz2bwyup.us.auth0.com")
#AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-web-extractor")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-content-api")
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "https://http-mcp-oauth-server-2.onrender.com")

# OAuth endpoints
OAUTH_ISSUER = f"https://{AUTH0_DOMAIN}/"
JWKS_URI = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
  
# Your existing Auth0 configuration  
#AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "dev-xrlojx8grz2bwyup.us.auth0.com")  
#AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", "https://mcp-content-api")  
#RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "https://http-mcp-oauth-server-2.onrender.com")  
  
# OAuth endpoints  
#OAUTH_ISSUER = f"https://{AUTH0_DOMAIN}/"  
#JWKS_URI = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"  
  
class Auth0OAuthProvider(RemoteAuthProvider):  
    """Custom OAuth provider that extends RemoteAuthProvider with Auth0 authorization endpoints."""  
      
    def __init__(self, auth0_domain: str, resource_server_url: str, audience: str):  
        # Configure token validation for Auth0  
        token_verifier = JWTVerifier(  
            jwks_uri=f"https://{auth0_domain}/.well-known/jwks.json",  
            issuer=f"https://{auth0_domain}/",  
            audience=audience  
        )  
          
        # Initialize RemoteAuthProvider  
        super().__init__(  
            token_verifier=token_verifier,  
            authorization_servers=[AnyHttpUrl(f"https://{auth0_domain}")],  
            resource_server_url=resource_server_url  
        )  
          
        self.auth0_domain = auth0_domain  
      
    def get_routes(self) -> list[Route]:  
        """Get OAuth routes including the /authorize endpoint for Claude Desktop."""  
        # Get the standard protected resource routes from RemoteAuthProvider  
        routes = super().get_routes()  
          
        async def authorize_endpoint(request):  
            """Redirect to Auth0 for authentication with all query parameters."""  
            auth0_authorize_url = f"https://{self.auth0_domain}/authorize"  
            # Forward all query parameters to Auth0  
            query_string = str(request.url.query)  
            redirect_url = f"{auth0_authorize_url}?{query_string}" if query_string else auth0_authorize_url  
            return RedirectResponse(redirect_url)  
          
        async def token_endpoint(request):  
            """Proxy token requests to Auth0."""  
            # This is a simple proxy - in production you might want more sophisticated handling  
            import httpx  
            from starlette.responses import JSONResponse  
              
            try:  
                async with httpx.AsyncClient() as client:  
                    # Forward the token request to Auth0  
                    auth0_token_url = f"https://{self.auth0_domain}/oauth/token"  
                      
                    # Get the request body  
                    body = await request.body()  
                    headers = dict(request.headers)  
                      
                    # Forward to Auth0  
                    response = await client.post(  
                        auth0_token_url,  
                        content=body,  
                        headers={  
                            "Content-Type": headers.get("content-type", "application/x-www-form-urlencoded")  
                        }  
                    )  
                      
                    return JSONResponse(  
                        content=response.json(),  
                        status_code=response.status_code  
                    )  
            except Exception as e:  
                return JSONResponse(  
                    {"error": "server_error", "error_description": str(e)},  
                    status_code=500  
                )  
          
        async def oauth_authorization_server_metadata(request):  
            """Forward Auth0 OAuth authorization server metadata."""  
            import httpx  
            from starlette.responses import JSONResponse  
              
            try:  
                async with httpx.AsyncClient() as client:  
                    response = await client.get(  
                        f"https://{self.auth0_domain}/.well-known/oauth-authorization-server"  
                    )  
                    response.raise_for_status()  
                    metadata = response.json()  
                      
                    # Update the metadata to point to our server for authorization/token endpoints  
                    metadata["authorization_endpoint"] = f"{self.resource_server_url}/authorize"  
                    metadata["token_endpoint"] = f"{self.resource_server_url}/token"  
                      
                    return JSONResponse(metadata)  
            except Exception as e:  
                return JSONResponse(  
                    {  
                        "error": "server_error",  
                        "error_description": f"Failed to fetch Auth0 metadata: {e}",  
                    },  
                    status_code=500,  
                )  
          
        # Add the OAuth endpoints that Claude Desktop expects  
        routes.extend([  
            Route("/authorize", authorize_endpoint, methods=["GET"]),  
            Route("/token", token_endpoint, methods=["POST"]),  
            Route("/.well-known/oauth-authorization-server", oauth_authorization_server_metadata, methods=["GET"])  
        ])  
          
        return routes  
  
# Create the custom auth provider  
auth = Auth0OAuthProvider(  
    auth0_domain=AUTH0_DOMAIN,  
    resource_server_url=RESOURCE_SERVER_URL,  
    audience=AUTH0_AUDIENCE  
)  
  
# Create FastMCP server with the custom auth provider  
mcp = FastMCP(name="Company API", auth=auth)  
  
@mcp.tool  
def test_str(name: str) -> str:  
    print(f"Tool called at: {datetime.now()}", file=sys.stderr)  
    return f"Hello, {name}!"  
  
if __name__ == "__main__":  
    port = int(os.environ.get("PORT", 8000))  
    # Start an HTTP server  
    mcp.run(transport="http", host="0.0.0.0", port=port)