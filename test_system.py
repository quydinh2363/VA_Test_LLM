"""
Test script for Security Testing Assistant
"""

import asyncio
import requests
import json
from typing import Dict, Any

# Configuration
API_BASE_URL = "http://localhost:8000"
UI_BASE_URL = "http://localhost:8501"

def test_api_health():
    """Test API health endpoint"""
    print("🔍 Testing API health...")
    try:
        response = requests.get(f"{API_BASE_URL}/health")
        if response.status_code == 200:
            print("✅ API health check passed")
            return True
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API health check error: {e}")
        return False

def test_zap_connection():
    """Test ZAP connection"""
    print("🔍 Testing ZAP connection...")
    try:
        response = requests.get(f"{API_BASE_URL}/zap/status")
        if response.status_code == 200:
            data = response.json()
            if data.get("connected"):
                print("✅ ZAP connection successful")
                return True
            else:
                print(f"❌ ZAP connection failed: {data.get('error', 'Unknown error')}")
                return False
        else:
            print(f"❌ ZAP status check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ ZAP connection error: {e}")
        return False

def test_chat_api():
    """Test chat API"""
    print("🔍 Testing chat API...")
    try:
        payload = {
            "message": "Giải thích về XSS",
            "session_id": "test_session"
        }
        response = requests.post(f"{API_BASE_URL}/chat", json=payload)
        if response.status_code == 200:
            data = response.json()
            print("✅ Chat API test passed")
            print(f"   Intent: {data.get('intent')}")
            print(f"   Confidence: {data.get('confidence')}")
            return True
        else:
            print(f"❌ Chat API test failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Chat API error: {e}")
        return False

def test_payload_generation():
    """Test payload generation API"""
    print("🔍 Testing payload generation...")
    try:
        payload = {
            "vulnerability_type": "xss",
            "difficulty": "medium",
            "count": 3
        }
        response = requests.post(f"{API_BASE_URL}/payloads", json=payload)
        if response.status_code == 200:
            data = response.json()
            print("✅ Payload generation test passed")
            print(f"   Generated {len(data.get('payloads', []))} payloads")
            return True
        else:
            print(f"❌ Payload generation test failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Payload generation error: {e}")
        return False

def test_intent_classification():
    """Test intent classification"""
    print("🔍 Testing intent classification...")
    try:
        test_messages = [
            "Giải thích về XSS",
            "Tạo payload cho SQL injection",
            "Quét website https://juice-shop.herokuapp.com",
            "Help"
        ]
        
        for message in test_messages:
            payload = {"message": message}
            response = requests.post(f"{API_BASE_URL}/intent", json=payload)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Intent classification for '{message}': {data.get('intent')}")
            else:
                print(f"❌ Intent classification failed for '{message}': {response.status_code}")
                return False
        
        return True
    except Exception as e:
        print(f"❌ Intent classification error: {e}")
        return False

def test_ui_access():
    """Test UI accessibility"""
    print("🔍 Testing UI accessibility...")
    try:
        response = requests.get(UI_BASE_URL)
        if response.status_code == 200:
            print("✅ UI is accessible")
            return True
        else:
            print(f"❌ UI access failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ UI access error: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("🚀 Starting Security Testing Assistant System Tests")
    print("=" * 50)
    
    tests = [
        ("API Health", test_api_health),
        ("ZAP Connection", test_zap_connection),
        ("Chat API", test_chat_api),
        ("Payload Generation", test_payload_generation),
        ("Intent Classification", test_intent_classification),
        ("UI Access", test_ui_access)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name} test...")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<25} {status}")
        if result:
            passed += 1
    
    print("=" * 50)
    print(f"Total: {total}, Passed: {passed}, Failed: {total - passed}")
    
    if passed == total:
        print("🎉 All tests passed! System is ready to use.")
    else:
        print("⚠️  Some tests failed. Please check the configuration.")
    
    return passed == total

def main():
    """Main function"""
    try:
        success = run_all_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
