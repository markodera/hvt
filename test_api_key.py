"""
Quick test script to verify API key authentication works correctly.

Usage:
    python test_api_key.py <api_key>

Example:
    python test_api_key.py hvt_live_df7ec39866f7880297574e7d81629853e2ee6c7028c30b40160110af24598ecd
"""

import sys
import requests

def test_api_key(api_key):
    base_url = "http://localhost:8000"
    
    print("=" * 80)
    print("API Key Authentication Test")
    print("=" * 80)
    print(f"API Key: {api_key[:20]}...{api_key[-10:]}")
    print()
    
    # Test 1: Using only API key (should work)
    print("Test 1: Using ONLY X-API-Key header")
    print("-" * 80)
    headers = {
        "X-API-Key": api_key
    }
    
    response = requests.get(f"{base_url}/api/v1/users/", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:200]}")
    
    if response.status_code == 200:
        print("✓ SUCCESS: API key authentication works!")
    elif response.status_code == 403:
        print("✗ FAILED: Authenticated but permission denied")
    elif response.status_code == 401:
        print("✗ FAILED: Authentication failed - invalid API key or not registered")
    print()
    
    # Test 2: Using both JWT and API key (JWT will win)
    print("Test 2: Using BOTH Authorization and X-API-Key headers")
    print("-" * 80)
    print("(This simulates the Postman issue where both headers were sent)")
    headers_both = {
        "X-API-Key": api_key,
        "Authorization": "Bearer invalid_jwt_token"
    }
    
    response2 = requests.get(f"{base_url}/api/v1/users/", headers=headers_both)
    print(f"Status: {response2.status_code}")
    print(f"Response: {response2.text[:200]}")
    print("Note: JWT authentication runs first, so API key is ignored")
    print()
    
    print("=" * 80)
    print("IMPORTANT: When using API keys, DO NOT include Authorization header!")
    print("=" * 80)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_api_key.py <api_key>")
        print("Example: python test_api_key.py hvt_live_abc123...")
        sys.exit(1)
    
    api_key = sys.argv[1]
    test_api_key(api_key)
