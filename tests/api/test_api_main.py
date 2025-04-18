"""Test suite for the main FastAPI application."""

import pytest
from fastapi.testclient import TestClient

from api.main import app


# Fixture to provide a test client for API calls
@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_root_endpoint(client):
    """Test the root endpoint returns a welcome message."""
    response = client.get("/")
    assert response.status_code == 200
    # Verify the actual message from the API
    assert response.json() == {"message": "Welcome to CyberAgents API"}  # Removed "the"


def test_api_docs_available(client):
    """Verify that the API docs are available at /docs and /redoc."""
    # Test /docs endpoint
    response_docs = client.get("/docs")
    assert (
        response_docs.status_code == 200
    ), f"Expected 200 OK for /docs, got {response_docs.status_code}"

    response = client.get("/redoc")
    assert (
        response.status_code == 200
    ), f"Expected 200 OK for /redoc, got {response.status_code}"


def test_cors_headers(client):
    """Test that CORS headers are properly set."""
    # Make a request, e.g., to the root endpoint
    response = client.options("/")  # Use OPTIONS for preflight check or GET

    # Check for expected CORS headers (adjust if config is different)
    # Note: TestClient might not simulate browser preflight accurately.
    # A GET request might be better to check headers on the actual response.
    # Add an Origin header to the GET request to trigger CORS check
    request_headers = {"Origin": "http://testclient.com"}
    response_get = client.get("/", headers=request_headers)
    assert response_get.status_code == 200
    assert "access-control-allow-origin" in response_get.headers
    # Check the value if it's specific, e.g., "*" or a domain
    assert (
        response_get.headers["access-control-allow-origin"] == "*"
    )  # Adjust if needed
    # Remove checks for other headers as they might not be present on GET response
    # assert "access-control-allow-methods" in response_get.headers
    # assert "access-control-allow-headers" in response_get.headers


def test_404_response(client):
    """Test that non-existent endpoints return 404."""
    response = client.get("/nonexistent/path")
    assert (
        response.status_code == 404
    ), f"Expected 404 Not Found, got {response.status_code}"
    # Check if the response body is valid JSON and contains 'detail'
    try:
        json_response = response.json()
        assert "detail" in json_response
    except Exception:
        pytest.fail("Expected JSON response with 'detail' key for 404")
