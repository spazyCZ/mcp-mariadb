import unittest
from unittest.mock import Mock, AsyncMock, patch
import asyncio
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Route

# Import the TokenAuthMiddleware
from src.token_auth_middleware import TokenAuthMiddleware


class TestTokenAuthMiddleware(unittest.IsolatedAsyncioTestCase):
    """Test suite for TokenAuthMiddleware"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_token = "test-secret-token-123"
        
    async def asyncSetUp(self):
        """Set up async test fixtures"""
        pass

    async def asyncTearDown(self):
        """Clean up after async tests"""
        pass

    def _create_test_app(self, token=None):
        """Helper to create a test Starlette app with the middleware"""
        async def homepage(request):
            return JSONResponse({"message": "success"})

        app = Starlette(
            routes=[Route('/', homepage)],
            middleware=[Middleware(TokenAuthMiddleware, token=token)]
        )
        return app

    def test_no_token_configured_allows_all_requests(self):
        """When MCP_TOKEN is None/empty, middleware should allow all requests"""
        app = self._create_test_app(token=None)
        client = TestClient(app)
        
        # Request without any auth headers should succeed
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "success"})

    def test_no_token_configured_with_empty_string(self):
        """When MCP_TOKEN is empty string, middleware should allow all requests"""
        app = self._create_test_app(token="")
        client = TestClient(app)
        
        # Request without any auth headers should succeed
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "success"})

    def test_valid_bearer_token_allows_request(self):
        """Valid Bearer token in Authorization header should allow request"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "Authorization": f"Bearer {self.test_token}"
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "success"})

    def test_valid_custom_header_token_allows_request(self):
        """Valid token in x-mcp-token header should allow request"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "x-mcp-token": self.test_token
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "success"})

    def test_invalid_bearer_token_rejects_request(self):
        """Invalid Bearer token should reject request with 401"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "Authorization": "Bearer wrong-token"
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_invalid_custom_header_token_rejects_request(self):
        """Invalid token in x-mcp-token header should reject request with 401"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "x-mcp-token": "wrong-token"
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_no_auth_headers_rejects_request(self):
        """Request without any auth headers should be rejected when token is configured"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        response = client.get('/')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_bearer_token_case_insensitive(self):
        """Bearer keyword should be case-insensitive"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        # Test with lowercase 'bearer'
        response = client.get('/', headers={
            "Authorization": f"bearer {self.test_token}"
        })
        self.assertEqual(response.status_code, 200)
        
        # Test with mixed case 'BeArEr'
        response = client.get('/', headers={
            "Authorization": f"BeArEr {self.test_token}"
        })
        self.assertEqual(response.status_code, 200)

    def test_bare_token_in_authorization_header(self):
        """Authorization header with bare token (no 'Bearer' prefix) should work"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "Authorization": self.test_token
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "success"})

    def test_token_with_whitespace_is_trimmed(self):
        """Tokens with leading/trailing whitespace should be trimmed"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        # Bearer token with extra spaces
        response = client.get('/', headers={
            "Authorization": f"Bearer  {self.test_token}  "
        })
        self.assertEqual(response.status_code, 200)
        
        # Custom header with extra spaces
        response = client.get('/', headers={
            "x-mcp-token": f"  {self.test_token}  "
        })
        self.assertEqual(response.status_code, 200)

    def test_authorization_header_takes_precedence_over_custom_header(self):
        """When both headers present, Authorization header should be checked"""
        app = self._create_test_app(token=self.test_token)
        client = TestClient(app)
        
        # Valid Authorization, invalid custom header - should succeed
        response = client.get('/', headers={
            "Authorization": f"Bearer {self.test_token}",
            "x-mcp-token": "wrong-token"
        })
        self.assertEqual(response.status_code, 200)

    def test_post_request_with_valid_token(self):
        """POST requests should also be protected by token auth"""
        async def post_endpoint(request):
            return JSONResponse({"message": "post success"})
        
        app = Starlette(
            routes=[Route('/', post_endpoint, methods=['POST'])],
            middleware=[Middleware(TokenAuthMiddleware, token=self.test_token)]
        )
        client = TestClient(app)
        
        # Valid token
        response = client.post('/', headers={
            "Authorization": f"Bearer {self.test_token}"
        })
        self.assertEqual(response.status_code, 200)
        
        # Invalid token
        response = client.post('/', headers={
            "Authorization": "Bearer wrong-token"
        })
        self.assertEqual(response.status_code, 401)

    def test_special_characters_in_token(self):
        """Tokens with special characters should work correctly"""
        special_token = "a1b2c3!@#$%^&*()_+-=[]{}|;':,.<>?/~`"
        app = self._create_test_app(token=special_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "Authorization": f"Bearer {special_token}"
        })
        self.assertEqual(response.status_code, 200)

    def test_long_token(self):
        """Long tokens (like base64 encoded) should work correctly"""
        long_token = "VGhpc0lzQVZlcnlMb25nVG9rZW5UaGF0Q291bGRCZUJhc2U2NEVuY29kZWRPckEzMkJ5dGVSYW5kb21TdHJpbmc="
        app = self._create_test_app(token=long_token)
        client = TestClient(app)
        
        response = client.get('/', headers={
            "Authorization": f"Bearer {long_token}"
        })
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
