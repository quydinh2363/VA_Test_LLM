#!/usr/bin/env python3
"""
AI Payload Generator Demo Script

This script demonstrates the new AI-powered payload generation capabilities
including intelligent payload creation, contextual payloads, chain payloads,
and bypass techniques.
"""

import asyncio
import json
import aiohttp
import time
from typing import Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API base URL
API_BASE_URL = "http://localhost:8000"

# Test targets
TEST_TARGETS = {
    "php_app": "http://demo.testfire.net/search.php",
    "asp_app": "http://demo.testfire.net/login.asp",
    "api_endpoint": "http://demo.testfire.net/api/users",
    "upload_page": "http://demo.testfire.net/upload.php"
}

async def test_ai_payload_generation():
    """Test AI-powered payload generation"""
    logger.info("🤖 Testing AI-Powered Payload Generation...")
    
    url = f"{API_BASE_URL}/ai-payloads/generate"
    payload = {
        "target_url": TEST_TARGETS["php_app"],
        "vulnerability_type": "xss",
        "context": "url_parameter",
        "input_field": "search",
        "current_value": "test",
        "custom_requirements": "Bypass WAF and input validation",
        "difficulty_level": "hard",
        "bypass_techniques": ["encoding", "case_manipulation", "whitespace"]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ AI Payload Generation Completed")
                    logger.info(f"   Target URL: {result['target_url']}")
                    logger.info(f"   Vulnerability Type: {result['vulnerability_type']}")
                    logger.info(f"   Total Payloads: {result['total_payloads']}")
                    logger.info(f"   AI Generated: {result['ai_generated']}")
                    
                    # Show some payload examples
                    for i, payload_data in enumerate(result['payloads'][:3]):
                        logger.info(f"   Payload {i+1}: {payload_data['technique']}")
                        logger.info(f"     Success Probability: {payload_data['success_probability']:.2%}")
                        logger.info(f"     Risk Level: {payload_data['risk_level']}")
                        logger.info(f"     AI Reasoning: {payload_data['ai_reasoning'][:100]}...")
                    
                    return result
                else:
                    logger.error(f"❌ AI Payload Generation Failed: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"❌ Error in AI payload generation: {e}")
        return None

async def test_contextual_payloads():
    """Test contextual payload generation"""
    logger.info("🎯 Testing Contextual Payload Generation...")
    
    url = f"{API_BASE_URL}/ai-payloads/contextual"
    payload = {
        "target_url": TEST_TARGETS["api_endpoint"],
        "context": "api_endpoint",
        "vulnerability_type": "sqli"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Contextual Payload Generation Completed")
                    logger.info(f"   Context: {result['context']}")
                    logger.info(f"   Total Payloads: {result['total_payloads']}")
                    logger.info(f"   Context Optimized: {result['context_optimized']}")
                    
                    # Show payload examples
                    for i, payload_data in enumerate(result['payloads'][:2]):
                        logger.info(f"   Contextual Payload {i+1}: {payload_data['technique']}")
                        logger.info(f"     Success Probability: {payload_data['success_probability']:.2%}")
                    
                    return result
                else:
                    logger.error(f"❌ Contextual Payload Generation Failed: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"❌ Error in contextual payload generation: {e}")
        return None

async def test_chain_payloads():
    """Test vulnerability chain payload generation"""
    logger.info("🔗 Testing Vulnerability Chain Payload Generation...")
    
    url = f"{API_BASE_URL}/ai-payloads/chain"
    payload = {
        "target_url": TEST_TARGETS["php_app"],
        "vulnerability_chain": ["lfi", "rce", "sqli"]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Chain Payload Generation Completed")
                    logger.info(f"   Vulnerability Chain: {' -> '.join(result['vulnerability_chain'])}")
                    logger.info(f"   Total Chains: {result['total_chains']}")
                    logger.info(f"   Chain Optimized: {result['chain_optimized']}")
                    
                    # Show chain payloads
                    for vuln_type, payloads in result['chain_payloads'].items():
                        logger.info(f"   {vuln_type.upper()}: {len(payloads)} payloads")
                        for i, payload_data in enumerate(payloads[:1]):
                            logger.info(f"     Chain Payload {i+1}: {payload_data['technique']}")
                    
                    return result
                else:
                    logger.error(f"❌ Chain Payload Generation Failed: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"❌ Error in chain payload generation: {e}")
        return None

async def test_bypass_payloads():
    """Test bypass payload generation"""
    logger.info("🛡️ Testing Bypass Payload Generation...")
    
    url = f"{API_BASE_URL}/ai-payloads/bypass"
    payload = {
        "original_payload": "<script>alert('XSS')</script>",
        "bypass_techniques": ["encoding", "case_manipulation", "whitespace"]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Bypass Payload Generation Completed")
                    logger.info(f"   Original Payload: {result['original_payload']}")
                    logger.info(f"   Bypass Techniques: {', '.join(result['bypass_techniques'])}")
                    logger.info(f"   Total Bypasses: {result['total_bypasses']}")
                    logger.info(f"   Bypass Generated: {result['bypass_generated']}")
                    
                    # Show some bypass examples
                    for i, bypass_payload in enumerate(result['bypass_payloads'][:3]):
                        logger.info(f"   Bypass {i+1}: {bypass_payload}")
                    
                    return result
                else:
                    logger.error(f"❌ Bypass Payload Generation Failed: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"❌ Error in bypass payload generation: {e}")
        return None

async def test_target_analysis():
    """Test target analysis for payload generation"""
    logger.info("🔍 Testing Target Analysis for Payload Generation...")
    
    target_url = TEST_TARGETS["php_app"]
    url = f"{API_BASE_URL}/ai-payloads/analyze/{target_url}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Target Analysis Completed")
                    logger.info(f"   Target URL: {result['target_url']}")
                    
                    # Show analysis results
                    analysis = result['analysis']
                    logger.info(f"   Technology Stack: {analysis.get('technology_stack', {})}")
                    logger.info(f"   WAF Detected: {analysis.get('waf_detected', False)}")
                    logger.info(f"   Framework: {analysis.get('framework_detection', {})}")
                    
                    # Show recommendations
                    recommendations = result['recommendations']
                    logger.info(f"   Recommended Vuln Types: {recommendations['vulnerability_types']}")
                    logger.info(f"   Recommended Contexts: {recommendations['payload_contexts']}")
                    logger.info(f"   Recommended Bypasses: {recommendations['bypass_techniques']}")
                    
                    return result
                else:
                    logger.error(f"❌ Target Analysis Failed: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"❌ Error in target analysis: {e}")
        return None

async def test_payload_statistics():
    """Test payload generation statistics"""
    logger.info("📊 Testing Payload Generation Statistics...")
    
    url = f"{API_BASE_URL}/ai-payloads/statistics"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Payload Statistics Retrieved")
                    
                    # Show statistics
                    stats = result['statistics']
                    logger.info(f"   Total Payloads: {stats['total_payloads']}")
                    logger.info(f"   Vulnerability Types: {stats['vulnerability_types']}")
                    logger.info(f"   Difficulty Distribution: {stats['difficulty_distribution']}")
                    
                    # Show AI capabilities
                    ai_capabilities = result['ai_capabilities']
                    logger.info(f"   AI Capabilities:")
                    for capability, enabled in ai_capabilities.items():
                        logger.info(f"     {capability}: {'✅' if enabled else '❌'}")
                    
                    return result
                else:
                    logger.error(f"❌ Payload Statistics Failed: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"❌ Error getting payload statistics: {e}")
        return None

async def test_intelligent_payload_scenarios():
    """Test various intelligent payload scenarios"""
    logger.info("🧠 Testing Intelligent Payload Scenarios...")
    
    scenarios = [
        {
            "name": "PHP Login Form XSS",
            "payload": {
                "target_url": "http://demo.testfire.net/login.php",
                "vulnerability_type": "xss",
                "context": "form_field",
                "input_field": "username",
                "custom_requirements": "Bypass PHP input validation and WAF"
            }
        },
        {
            "name": "API Endpoint SQL Injection",
            "payload": {
                "target_url": "http://demo.testfire.net/api/users",
                "vulnerability_type": "sqli",
                "context": "json_body",
                "input_field": "user_id",
                "custom_requirements": "JSON-based SQL injection with error-based technique"
            }
        },
        {
            "name": "File Upload LFI",
            "payload": {
                "target_url": "http://demo.testfire.net/upload.php",
                "vulnerability_type": "lfi",
                "context": "file_upload",
                "input_field": "filename",
                "custom_requirements": "Path traversal to read sensitive files"
            }
        }
    ]
    
    results = {}
    
    for scenario in scenarios:
        logger.info(f"   Testing: {scenario['name']}")
        
        url = f"{API_BASE_URL}/ai-payloads/generate"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=scenario['payload']) as response:
                    if response.status == 200:
                        result = await response.json()
                        results[scenario['name']] = {
                            "success": True,
                            "payloads_count": result['total_payloads'],
                            "ai_generated": result['ai_generated']
                        }
                        logger.info(f"     ✅ Generated {result['total_payloads']} payloads")
                    else:
                        results[scenario['name']] = {"success": False, "error": response.status}
                        logger.info(f"     ❌ Failed with status {response.status}")
        except Exception as e:
            results[scenario['name']] = {"success": False, "error": str(e)}
            logger.info(f"     ❌ Error: {e}")
    
    return results

async def run_ai_payload_generator_demo():
    """Run the complete AI payload generator demo"""
    logger.info("🚀 Starting AI Payload Generator Demo")
    logger.info("=" * 60)
    
    start_time = time.time()
    
    # Run all tests
    results = {}
    
    # 1. AI Payload Generation
    results['ai_payload_generation'] = await test_ai_payload_generation()
    logger.info("-" * 40)
    
    # 2. Contextual Payloads
    results['contextual_payloads'] = await test_contextual_payloads()
    logger.info("-" * 40)
    
    # 3. Chain Payloads
    results['chain_payloads'] = await test_chain_payloads()
    logger.info("-" * 40)
    
    # 4. Bypass Payloads
    results['bypass_payloads'] = await test_bypass_payloads()
    logger.info("-" * 40)
    
    # 5. Target Analysis
    results['target_analysis'] = await test_target_analysis()
    logger.info("-" * 40)
    
    # 6. Payload Statistics
    results['payload_statistics'] = await test_payload_statistics()
    logger.info("-" * 40)
    
    # 7. Intelligent Scenarios
    results['intelligent_scenarios'] = await test_intelligent_payload_scenarios()
    logger.info("-" * 40)
    
    # Calculate total time
    total_time = time.time() - start_time
    
    # Summary
    logger.info("📋 Demo Summary")
    logger.info("=" * 60)
    logger.info(f"Total Demo Time: {total_time:.2f} seconds")
    
    # Count successful tests
    successful_tests = sum(1 for result in results.values() if result is not None and result.get('success', False))
    total_tests = len(results)
    
    logger.info(f"Successful Tests: {successful_tests}/{total_tests}")
    logger.info(f"Success Rate: {successful_tests/total_tests:.2%}")
    
    # Show AI capabilities summary
    logger.info("🤖 AI Payload Generator Capabilities:")
    logger.info("   ✅ Intelligent payload generation")
    logger.info("   ✅ Context-aware payloads")
    logger.info("   ✅ Vulnerability chain payloads")
    logger.info("   ✅ WAF bypass techniques")
    logger.info("   ✅ Target analysis and recommendations")
    logger.info("   ✅ Multiple encoding methods")
    logger.info("   ✅ Success probability estimation")
    logger.info("   ✅ AI reasoning for payload choices")
    
    # Save results to file
    with open("ai_payload_generator_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info("💾 Results saved to: ai_payload_generator_results.json")
    logger.info("🎉 AI Payload Generator Demo Completed!")
    
    return results

def main():
    """Main function"""
    print("🤖 AI Payload Generator Demo")
    print("=" * 60)
    print("This demo showcases the new AI-powered payload generation capabilities:")
    print("• Intelligent payload generation with AI analysis")
    print("• Context-aware payloads for different scenarios")
    print("• Vulnerability chain payloads")
    print("• WAF bypass techniques")
    print("• Target analysis and recommendations")
    print("• Multiple encoding and bypass methods")
    print("• Success probability estimation")
    print("• AI reasoning for payload choices")
    print("=" * 60)
    
    # Run the demo
    asyncio.run(run_ai_payload_generator_demo())

if __name__ == "__main__":
    main()
