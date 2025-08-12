"""
OAuth-enabled MCP Client using Auth0
Implements Authorization Code flow with PKCE
"""

import os
import json
import base64
import hashlib
import secrets
import webbrowser
import asyncio
from typing import Optional
from urllib.parse import urlencode, parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import requests
from anthropic import Anthropic
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv('env')

class AuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback"""
    
    def do_GET(self):
        # Parse the authorization code from callback
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        if 'code' in query_params:
            self.server.authorization_code = query_params['code'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
            <html><body>
            <h1>Authorization Successful!</h1>
            <p>You can now close this window and return to the application.</p>
            </body></html>
            ''')
        elif 'error' in query_params:
            self.server.error = query_params['error'][0]
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f'''
            <html><body>
            <h1>Authorization Error</h1>
            <p>Error: {query_params['error'][0]}</p>
            <p>Description: {query_params.get('error_description', ['Unknown error'])[0]}</p>
            </body></html>
            '''.encode())
        
        # Signal the server to stop
        Thread(target=self.server.shutdown).start()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

class Auth0Client:
    """Auth0 OAuth client with PKCE"""
    
    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID") 
        self.audience = os.environ.get("AUTH0_AUDIENCE")
        self.redirect_uri = "http://localhost:8080/callback"
        self.access_token = None
        self.refresh_token = None
        
        if not all([self.domain, self.client_id, self.audience]):
            raise ValueError("Missing Auth0 configuration in environment")
    
    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    async def authenticate(self) -> bool:
        """Perform OAuth authentication flow"""
        print("Starting Auth0 authentication...")
        
        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_pair()
        
        # Build authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'audience': self.audience,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'state': secrets.token_urlsafe(16)
        }
        
        auth_url = f"https://{self.domain}/authorize?" + urlencode(auth_params)
        
        print(f"Opening browser for authentication...")
        print(f"If browser doesn't open, visit: {auth_url}")
        
        # Start local callback server
        server = HTTPServer(('localhost', 8080), AuthCallbackHandler)
        server.authorization_code = None
        server.error = None
        
        # Open browser
        webbrowser.open(auth_url)
        
        print("Waiting for authorization callback...")
        
        # Handle callback
        server.handle_request()
        
        if hasattr(server, 'error') and server.error:
            print(f"Authentication failed: {server.error}")
            return False
        
        if not hasattr(server, 'authorization_code') or not server.authorization_code:
            print("No authorization code received")
            return False
        
        # Exchange code for tokens
        return await self.exchange_code_for_token(server.authorization_code, code_verifier)
    
    async def exchange_code_for_token(self, auth_code: str, code_verifier: str) -> bool:
        """Exchange authorization code for access token"""
        print("Exchanging authorization code for access token...")
        
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier
        }
        
        try:
            response = requests.post(
                f"https://{self.domain}/oauth/token",
                json=token_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            
            token_response = response.json()
            self.access_token = token_response.get('access_token')
            self.refresh_token = token_response.get('refresh_token')
            
            if self.access_token:
                print("Authentication successful! Access token obtained.")
                return True
            else:
                print("No access token in response")
                return False
                
        except Exception as e:
            print(f"Token exchange failed: {e}")
            return False

class MCPOAuthClient:
    """MCP Client with OAuth support"""
    
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.auth_client = Auth0Client()
        self.anthropic = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.session: Optional[ClientSession] = None    
        self.tools = []
        self.client_context = None
        self.session_context = None

    async def authenticate(self) -> bool:
        """Authenticate with Auth0"""
        return await self.auth_client.authenticate()

    async def connect(self):
        """Connect to the streamable HTTP MCP server"""
        print(f"Connecting to MCP server at {self.server_url}")
        
        try:
            # Connect to the streamable HTTP server
            self.client_context = streamablehttp_client(self.server_url)
            read_stream, write_stream, _ = await self.client_context.__aenter__()
            
            # Create a session using the client streams
            self.session_context = ClientSession(read_stream, write_stream)
            self.session = await self.session_context.__aenter__()
            
            # Initialize the session
            await self.session.initialize()
            
            # Get available tools
            resp = await self.session.list_tools()
            self.tools = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.inputSchema,
                }
                for t in resp.tools
            ]
            
            print(f"Connected! Available tools: {[t['name'] for t in self.tools]}")
            return True
            
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    async def test_oauth_tool(self, url: str) -> bool:
        """Test OAuth-protected tool"""
        if not self.session or not self.auth_client.access_token:
            print("Not connected or not authenticated")
            return False
            
        try:
            print(f"Testing OAuth-protected content extraction for: {url}")
            result = await self.session.call_tool("extract_web_content_oauth", {
                "url": url,
                "access_token": self.auth_client.access_token
            })
            print(f"OAuth Tool result: {result.content[0].text[:300]}...")
            return True
            
        except Exception as e:
            print(f"OAuth tool test failed: {e}")
            return False

    async def test_token_validation(self) -> bool:
        """Test token validation tool"""
        if not self.session or not self.auth_client.access_token:
            print("Not connected or not authenticated")
            return False
            
        try:
            print("Testing token validation...")
            result = await self.session.call_tool("validate_token", {
                "access_token": self.auth_client.access_token
            })
            print(f"Token validation result: {result.content[0].text}")
            return True
            
        except Exception as e:
            print(f"Token validation test failed: {e}")
            return False

    async def process_query(self, query: str) -> str:
        """Process a user query using Claude with available MCP tools"""
        print(f"Processing query: {query}")
        
        # Send message to Claude with tool list
        claude_resp = self.anthropic.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": query}],
            tools=self.tools,
        )

        output = []
        
        for chunk in claude_resp.content:
            if chunk.type == "text":
                output.append(chunk.text)
            elif chunk.type == "tool_use":
                name, args = chunk.name, chunk.input
                print(f"Calling tool: {name} with args: {args}")
                
                # Add access token if using OAuth-protected tool
                if name == "extract_web_content_oauth" and self.auth_client.access_token:
                    args["access_token"] = self.auth_client.access_token
                
                # Call the MCP tool
                result = await self.session.call_tool(name, args)
                print(f"Tool result: {result.content}")
                
                output.append(f"\n[Tool Result from {name}]\n{result.content[0].text}")

        return "\n".join(output)

    async def chat_loop(self):
        """Interactive chat loop with OAuth-protected tools"""
        print("\n" + "="*60)
        print("🎉 INTERACTIVE CHAT WITH OAUTH-PROTECTED TOOLS")
        print("="*60)
        print("You can now ask questions and use OAuth-protected web content extraction!")
        print("\nExamples:")
        print("  - 'Extract content from https://example.com'")
        print("  - 'Get the title of https://github.com'")
        print("  - 'What's on the OpenAI website?'")
        print("\nType 'exit' to quit\n")
        
        while True:
            try:
                user_input = input("You: ").strip()
                if user_input.lower() in ("exit", "quit"):
                    break
                    
                if not user_input:
                    continue
                    
                response = await self.process_query(user_input)
                print("Assistant:", response)
                print("-" * 50)
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Error processing query: {e}")
                print("-" * 50)

    async def close(self):
        """Clean up connections"""
        try:
            if self.session_context:
                await self.session_context.__aexit__(None, None, None)
            if self.client_context:
                await self.client_context.__aexit__(None, None, None)
            print("Disconnected from MCP server")
        except Exception as e:
            print(f"Error during cleanup: {e}")

async def test_oauth_flow():
    """Test complete OAuth flow"""
    print("=== MCP OAuth Flow Test ===")
    
    client = MCPOAuthClient("http://localhost:8000/mcp")
    
    try:
        # Step 1: Authenticate with Auth0
        print("\n1. Authenticating with Auth0...")
        authenticated = await client.authenticate()
        if not authenticated:
            print("FAILED: Authentication failed")
            return
        
        print("SUCCESS: Authentication completed")
        
        # Step 2: Connect to MCP server
        print("\n2. Connecting to MCP server...")
        connected = await client.connect()
        if not connected:
            print("FAILED: Could not connect to MCP server")
            return
        
        print("SUCCESS: Connected to MCP server")
        
        # Step 3: Test token validation
        print("\n3. Testing token validation...")
        token_valid = await client.test_token_validation()
        if not token_valid:
            print("FAILED: Token validation failed")
            return
        
        print("SUCCESS: Token validation passed")
        
        # Step 4: Test OAuth-protected tool
        print("\n4. Testing OAuth-protected content extraction...")
        tool_result = await client.test_oauth_tool("https://httpbin.org/html")
        if not tool_result:
            print("FAILED: OAuth tool test failed")
            return
        
        print("SUCCESS: OAuth-protected tool worked")
        
        print("\n=== ALL OAUTH TESTS PASSED ===")
        
        # Step 5: Interactive chat with OAuth-protected tools
        await client.chat_loop()
        
    except Exception as e:
        print(f"Test failed with error: {e}")
    finally:
        await client.close()

if __name__ == "__main__":
    print("OAuth-enabled MCP Client")
    print("Make sure the OAuth server is running at http://localhost:8000/mcp")
    print("This will open your browser for Auth0 authentication")
    print()
    
    try:
        asyncio.run(test_oauth_flow())
    except KeyboardInterrupt:
        print("\nTest interrupted by user")