"""
Test audit logging system
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_audit_trail():
    print("=" * 80)
    print("Testing Audit Logging System")
    print("=" * 80)
    
    # 1. Register a user (should log USER_REGISTER)
    print("\n1. Registering user...")
    response = requests.post(f"{BASE_URL}/api/v1/auth/register/", json={
        "email": "audit_test@example.com",
        "password1": "TestPass123!",
        "password2": "TestPass123!",
        "first_name": "Audit",
        "last_name": "Test"
    })
    print(f"Status: {response.status_code}")
    
    # Check Django admin at http://localhost:8000/admin/authentication/auditlog/
    print("\n✓ Check Django admin for USER_REGISTER event")
    print("  http://localhost:8000/admin/authentication/auditlog/")
    
    input("\nPress Enter to continue to role change test...")
    
    # 2. Change user role (requires login first)
    # ... you can add more tests ...

if __name__ == "__main__":
    test_audit_trail()