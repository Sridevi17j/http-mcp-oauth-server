from fastmcp import FastMCP  
from fastmcp.server.auth import RemoteAuthProvider  
from fastmcp.server.auth.providers.jwt import JWTVerifier  
from pydantic import AnyHttpUrl  
from starlette.routing import Route  
from starlette.responses import RedirectResponse  
import os  
  
class GoogleOAuthProvider(RemoteAuthProvider):  
    """Custom OAuth provider that extends RemoteAuthProvider with Google OAuth endpoints."""  
      
    def __init__(self, resource_server_url: str, audience: str):  
        # Configure token validation for Google OAuth  
        token_verifier = JWTVerifier(  
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",  
            issuer="https://accounts.google.com",  
            audience=audience,  
            algorithm="RS256"  # Google uses RS256 by default  
        )  
          
        # Initialize RemoteAuthProvider  
        super().__init__(  
            token_verifier=token_verifier,  
            authorization_servers=[AnyHttpUrl("https://accounts.google.com")],  
            resource_server_url=resource_server_url  
        )  
      
    def get_routes(self) -> list[Route]:  
        """Get OAuth routes including the /authorize endpoint for MCP clients."""  
        routes = super().get_routes()  
          
        async def authorize_endpoint(request):  
            """Redirect to Google for authentication with all query parameters."""  
            google_authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"  
            query_string = str(request.url.query)  
            redirect_url = f"{google_authorize_url}?{query_string}" if query_string else google_authorize_url  
            return RedirectResponse(redirect_url)  
          
        async def token_endpoint(request):  
            """Proxy token requests to Google."""  
            import httpx  
            from starlette.responses import JSONResponse  
              
            try:  
                async with httpx.AsyncClient() as client:  
                    google_token_url = "https://oauth2.googleapis.com/token"  
                    body = await request.body()  
                    headers = dict(request.headers)  
                      
                    response = await client.post(  
                        google_token_url,  
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
          
        # Add the OAuth endpoints that MCP clients expect  
        routes.extend([  
            Route("/authorize", authorize_endpoint, methods=["GET"]),  
            Route("/token", token_endpoint, methods=["POST"]),  
        ])  
          
        return routes  
  
# Create the Google OAuth provider  
auth = GoogleOAuthProvider(  
    resource_server_url="https://http-mcp-oauth-server-2.onrender.com",  
    audience="229310990363-om63cmohkhgljesggqp275eclpse0isf.apps.googleusercontent.com"  # Your Google OAuth client ID  
)  
  
mcp = FastMCP(name="Company API", auth=auth)  
  
@mcp.tool  
def test_str(name: str) -> str:  
    return f"Hello, {name}!"  
  
if __name__ == "__main__":  
    port = int(os.environ.get("PORT", 8000))  
    mcp.run(transport="http", host="0.0.0.0", port=port)