#!/usr/bin/env python3
"""
Demo script to test MCP call request functionality
"""

import asyncio
import json
from typing import Dict, Any
from app.security.mcp_client import MCPClient, MCPRequestType
from app.core.config import settings

async def test_mcp_call_request():
    """Test MCP call request functionality"""
    
    # Initialize MCP client
    mcp_client = MCPClient(settings.mcp_server_url, settings.mcp_api_key)
    
    try:
        # Test 1: Basic tool execution
        print("🔧 Test 1: Basic tool execution")
        request_data = {
            'request_id': 'test_nmap_001',
            'type': 'tool_execution',
            'target': 'scanme.nmap.org',
            'parameters': {
                'tool_name': 'nmap_scan',
                'ports': '1-100',
                'scan_type': 'stealth'
            },
            'context': {
                'user_intent': 'network_reconnaissance',
                'ethical_guidelines': ['authorized_scanning_only']
            },
            'priority': 'normal',
            'timeout': 300
        }
        
        response = await mcp_client.call_request(request_data)
        print(f"✅ Response: {response.success}")
        if response.success:
            print(f"📊 Data: {json.dumps(response.data, indent=2)}")
        else:
            print(f"❌ Error: {response.error}")
        
        # Test 2: Script generation
        print("\n📝 Test 2: Script generation")
        script_request = {
            'request_id': 'test_script_001',
            'type': 'script_generation',
            'target': 'https://demo.testfire.net',
            'parameters': {
                'script_type': 'sql_injection',
                'technique': 'boolean_based',
                'interactive': True
            },
            'context': {
                'user_intent': 'exploitation_script',
                'target_type': 'web_application'
            }
        }
        
        script_response = await mcp_client.call_request(script_request)
        print(f"✅ Script Response: {script_response.success}")
        if script_response.success:
            print(f"📄 Script: {script_response.data}")
        else:
            print(f"❌ Error: {script_response.error}")
        
        # Test 3: Batch requests
        print("\n🔄 Test 3: Batch requests")
        batch_requests = [
            {
                'request_id': 'batch_001',
                'type': 'tool_execution',
                'target': 'scanme.nmap.org',
                'parameters': {'tool_name': 'nuclei_scan', 'templates': 'cves'},
                'context': {'user_intent': 'vulnerability_scan'}
            },
            {
                'request_id': 'batch_002',
                'type': 'tool_execution',
                'target': 'scanme.nmap.org',
                'parameters': {'tool_name': 'ffuf_fuzzing', 'wordlist': 'common.txt'},
                'context': {'user_intent': 'directory_enumeration'}
            }
        ]
        
        batch_responses = await mcp_client.batch_request(batch_requests)
        print(f"✅ Batch Responses: {len(batch_responses)}")
        for i, resp in enumerate(batch_responses):
            print(f"  Request {i+1}: {'✅' if resp.success else '❌'} - {resp.request_id}")
        
        # Test 4: Stream request with callback
        print("\n🌊 Test 4: Stream request")
        
        async def stream_callback(chunk: Dict[str, Any]):
            """Callback for streaming responses"""
            print(f"📡 Stream chunk: {chunk.get('type', 'unknown')}")
        
        stream_request = {
            'request_id': 'stream_001',
            'type': 'pentest_execution',
            'target': 'https://demo.testfire.net',
            'parameters': {
                'tools': ['nmap_scan', 'nuclei_scan'],
                'phases': ['reconnaissance', 'vulnerability_scan']
            },
            'context': {'user_intent': 'comprehensive_pentest'},
            'timeout': 600
        }
        
        stream_response = await mcp_client.stream_request(stream_request, stream_callback)
        print(f"✅ Stream Response: {stream_response.success}")
        if stream_response.success:
            print(f"📊 Final Data: {json.dumps(stream_response.data, indent=2)}")
        else:
            print(f"❌ Error: {stream_response.error}")
        
        # Test 5: Chain exploit
        print("\n🔗 Test 5: Chain exploit")
        chain_request = {
            'request_id': 'chain_001',
            'type': 'chain_exploit',
            'target': 'https://demo.testfire.net',
            'parameters': {
                'exploit_chain': [
                    {
                        'step': 1,
                        'tool': 'nmap_scan',
                        'parameters': {'ports': '80,443,8080'},
                        'expected_output': 'open_ports'
                    },
                    {
                        'step': 2,
                        'tool': 'nuclei_scan',
                        'parameters': {'templates': 'vulnerabilities'},
                        'expected_output': 'vulnerabilities'
                    },
                    {
                        'step': 3,
                        'tool': 'sqlmap_injection',
                        'parameters': {'level': 1, 'risk': 1},
                        'expected_output': 'sql_injection'
                    }
                ]
            },
            'context': {'user_intent': 'automated_exploitation'},
            'timeout': 900
        }
        
        chain_response = await mcp_client.call_request(chain_request)
        print(f"✅ Chain Response: {chain_response.success}")
        if chain_response.success:
            print(f"🔗 Chain Result: {json.dumps(chain_response.data, indent=2)}")
        else:
            print(f"❌ Error: {chain_response.error}")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
    
    finally:
        await mcp_client.close()

async def test_burp_integration():
    """Test Burp Suite Pro integration"""
    from app.security.burp_client import BurpClient
    
    print("\n🔍 Test 6: Burp Suite Pro Integration")
    
    async with BurpClient() as burp_client:
        try:
            # Test connection
            connection_status = await burp_client.check_connection()
            print(f"✅ Burp Connection: {connection_status}")
            
            if connection_status:
                # Test adding target to scope
                scope_result = await burp_client.add_target_to_scope("https://demo.testfire.net")
                print(f"✅ Add to Scope: {scope_result}")
                
                # Test spider scan
                spider_scan_id = await burp_client.start_spider_scan("https://demo.testfire.net")
                print(f"✅ Spider Scan ID: {spider_scan_id}")
                
                # Test active scan
                active_scan_id = await burp_client.start_active_scan("https://demo.testfire.net")
                print(f"✅ Active Scan ID: {active_scan_id}")
                
                # Get scan status
                status = await burp_client.get_scan_status(spider_scan_id)
                print(f"✅ Scan Status: {status}")
                
                # Get issues
                issues = await burp_client.get_issues()
                print(f"✅ Issues Found: {len(issues)}")
                
        except Exception as e:
            print(f"❌ Burp test failed: {str(e)}")

async def main():
    """Main test function"""
    print("🚀 Starting MCP Call Request Tests")
    print("=" * 50)
    
    # Test MCP functionality
    await test_mcp_call_request()
    
    # Test Burp integration
    await test_burp_integration()
    
    print("\n" + "=" * 50)
    print("✅ All tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
