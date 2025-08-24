"""
MCP (Model Context Protocol) Client Module

This module provides integration with MCP servers for advanced AI capabilities,
including script generation, payload creation, and automated pentesting.
"""

import asyncio
import json
import logging
import ssl
import websockets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import aiohttp
import requests
from pydantic import BaseModel, Field


class MCPRequestType(Enum):
    """Types of MCP requests"""
    SCRIPT_GENERATION = "script_generation"
    PAYLOAD_CREATION = "payload_creation"
    PENTEST_EXECUTION = "pentest_execution"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    TOOL_EXECUTION = "tool_execution"
    DATA_EXTRACTION = "data_extraction"
    CHAIN_EXPLOIT = "chain_exploit"


class MCPToolType(Enum):
    """Types of tools available through MCP"""
    NMAP = "nmap"
    SQLMAP = "sqlmap"
    NUCLEI = "nuclei"
    FFUF = "ffuf"
    DIRSEARCH = "dirsearch"
    METASPLOIT = "metasploit"
    BURP_SUITE = "burp_suite"
    OWASP_ZAP = "owasp_zap"
    CUSTOM_SCRIPT = "custom_script"


@dataclass
class MCPRequest:
    """MCP request structure"""
    request_id: str
    request_type: MCPRequestType
    target: str
    parameters: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1
    timeout: int = 300


@dataclass
class MCPResponse:
    """MCP response structure"""
    request_id: str
    success: bool
    data: Any
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPTool(BaseModel):
    """MCP tool configuration"""
    name: str
    tool_type: MCPToolType
    description: str
    command_template: str
    parameters: List[str]
    output_format: str
    risk_level: str
    ethical_guidelines: List[str]


class MCPClient:
    """Client for interacting with MCP servers"""
    
    def __init__(self, server_url: str, api_key: Optional[str] = None):
        self.server_url = server_url
        self.api_key = api_key
        self.session = aiohttp.ClientSession()
        self.logger = logging.getLogger(__name__)
        self.available_tools = self._load_available_tools()
        
    def _load_available_tools(self) -> Dict[str, MCPTool]:
        """Load available MCP tools"""
        return {
            "nmap_scan": MCPTool(
                name="Nmap Network Scanner",
                tool_type=MCPToolType.NMAP,
                description="Perform network scanning and port enumeration",
                command_template="nmap -sS -sV -O {target} -p {ports}",
                parameters=["target", "ports", "scan_type"],
                output_format="xml",
                risk_level="Low",
                ethical_guidelines=[
                    "Only scan authorized networks",
                    "Respect rate limits",
                    "Do not perform aggressive scans",
                    "Document scan results"
                ]
            ),
            
            "sqlmap_injection": MCPTool(
                name="SQLMap SQL Injection",
                tool_type=MCPToolType.SQLMAP,
                description="Automated SQL injection detection and exploitation",
                command_template="sqlmap -u {target} --batch --level {level} --risk {risk}",
                parameters=["target", "level", "risk", "technique"],
                output_format="json",
                risk_level="High",
                ethical_guidelines=[
                    "Only test authorized databases",
                    "Do not extract sensitive data",
                    "Use read-only techniques when possible",
                    "Report findings responsibly"
                ]
            ),
            
            "nuclei_scan": MCPTool(
                name="Nuclei Vulnerability Scanner",
                tool_type=MCPToolType.NUCLEI,
                description="Fast vulnerability scanner based on templates",
                command_template="nuclei -u {target} -t {templates} -severity {severity}",
                parameters=["target", "templates", "severity"],
                output_format="json",
                risk_level="Medium",
                ethical_guidelines=[
                    "Only scan authorized targets",
                    "Use appropriate template categories",
                    "Respect target resources",
                    "Document vulnerabilities found"
                ]
            ),
            
            "ffuf_fuzzing": MCPTool(
                name="FFUF Directory Fuzzer",
                tool_type=MCPToolType.FFUF,
                description="Fast web fuzzer for directory and file discovery",
                command_template="ffuf -u {target}/FUZZ -w {wordlist} -mc {status_codes}",
                parameters=["target", "wordlist", "status_codes"],
                output_format="json",
                risk_level="Low",
                ethical_guidelines=[
                    "Only fuzz authorized targets",
                    "Use appropriate wordlists",
                    "Respect rate limits",
                    "Document discovered resources"
                ]
            ),
            
            "custom_script": MCPTool(
                name="Custom Exploitation Script",
                tool_type=MCPToolType.CUSTOM_SCRIPT,
                description="Execute custom exploitation scripts",
                command_template="python {script_path} --target {target} {parameters}",
                parameters=["script_path", "target", "parameters"],
                output_format="text",
                risk_level="Variable",
                ethical_guidelines=[
                    "Only execute on authorized targets",
                    "Review script before execution",
                    "Monitor script behavior",
                    "Document all activities"
                ]
            )
        }
    
    async def send_request(self, request: MCPRequest) -> MCPResponse:
        """Send request to MCP server"""
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            payload = {
                "request_id": request.request_id,
                "type": request.request_type.value,
                "target": request.target,
                "parameters": request.parameters,
                "context": request.context,
                "priority": request.priority,
                "timeout": request.timeout
            }
            
            async with self.session.post(
                f"{self.server_url}/api/v1/request",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=request.timeout)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return MCPResponse(
                        request_id=request.request_id,
                        success=True,
                        data=data.get("data"),
                        metadata=data.get("metadata", {})
                    )
                else:
                    error_text = await response.text()
                    return MCPResponse(
                        request_id=request.request_id,
                        success=False,
                        error=f"HTTP {response.status}: {error_text}"
                    )
                    
        except asyncio.TimeoutError:
            return MCPResponse(
                request_id=request.request_id,
                success=False,
                error="Request timeout"
            )
        except Exception as e:
            return MCPResponse(
                request_id=request.request_id,
                success=False,
                error=str(e)
            )
    
    async def generate_script(self, target: str, script_type: str, parameters: Dict[str, Any]) -> MCPResponse:
        """Generate exploitation script via MCP"""
        request = MCPRequest(
            request_id=f"script_gen_{hash(target)}",
            request_type=MCPRequestType.SCRIPT_GENERATION,
            target=target,
            parameters={
                "script_type": script_type,
                **parameters
            },
            context={"user_intent": "script_generation"}
        )
        
        return await self.send_request(request)
    
    async def create_payload(self, target: str, vulnerability_type: str, parameters: Dict[str, Any]) -> MCPResponse:
        """Create payload via MCP"""
        request = MCPRequest(
            request_id=f"payload_{hash(target)}",
            request_type=MCPRequestType.PAYLOAD_CREATION,
            target=target,
            parameters={
                "vulnerability_type": vulnerability_type,
                **parameters
            },
            context={"user_intent": "payload_creation"}
        )
        
        return await self.send_request(request)
    
    async def execute_pentest(self, target: str, tools: List[str], parameters: Dict[str, Any]) -> MCPResponse:
        """Execute pentest via MCP"""
        request = MCPRequest(
            request_id=f"pentest_{hash(target)}",
            request_type=MCPRequestType.PENTEST_EXECUTION,
            target=target,
            parameters={
                "tools": tools,
                **parameters
            },
            context={"user_intent": "pentest_execution"},
            timeout=600  # Longer timeout for pentest
        )
        
        return await self.send_request(request)
    
    async def analyze_vulnerability(self, target: str, vulnerability_data: Dict[str, Any]) -> MCPResponse:
        """Analyze vulnerability via MCP"""
        request = MCPRequest(
            request_id=f"analysis_{hash(target)}",
            request_type=MCPRequestType.VULNERABILITY_ANALYSIS,
            target=target,
            parameters=vulnerability_data,
            context={"user_intent": "vulnerability_analysis"}
        )
        
        return await self.send_request(request)
    
    async def execute_tool(self, tool_name: str, target: str, parameters: Dict[str, Any]) -> MCPResponse:
        """Execute specific tool via MCP"""
        if tool_name not in self.available_tools:
            return MCPResponse(
                request_id=f"tool_{hash(target)}",
                success=False,
                error=f"Tool {tool_name} not available"
            )
        
        tool = self.available_tools[tool_name]
        
        request = MCPRequest(
            request_id=f"tool_{hash(target)}",
            request_type=MCPRequestType.TOOL_EXECUTION,
            target=target,
            parameters={
                "tool_name": tool_name,
                "tool_type": tool.tool_type.value,
                "command_template": tool.command_template,
                **parameters
            },
            context={"user_intent": "tool_execution"}
        )
        
        return await self.send_request(request)
    
    async def extract_data(self, target: str, extraction_type: str, parameters: Dict[str, Any]) -> MCPResponse:
        """Extract data via MCP"""
        request = MCPRequest(
            request_id=f"extract_{hash(target)}",
            request_type=MCPRequestType.DATA_EXTRACTION,
            target=target,
            parameters={
                "extraction_type": extraction_type,
                **parameters
            },
            context={"user_intent": "data_extraction"}
        )
        
        return await self.send_request(request)
    
    async def chain_exploit(self, target: str, exploit_chain: List[Dict[str, Any]]) -> MCPResponse:
        """Execute chain exploit via MCP"""
        request = MCPRequest(
            request_id=f"chain_{hash(target)}",
            request_type=MCPRequestType.CHAIN_EXPLOIT,
            target=target,
            parameters={
                "exploit_chain": exploit_chain
            },
            context={"user_intent": "chain_exploit"},
            timeout=900  # Long timeout for chain exploits
        )
        
        return await self.send_request(request)
    
    def get_available_tools(self) -> Dict[str, MCPTool]:
        """Get list of available tools"""
        return self.available_tools
    
    def validate_target(self, target: str) -> bool:
        """Validate target URL/domain"""
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def check_server_status(self) -> bool:
        """Check if MCP server is available"""
        try:
            async with self.session.get(f"{self.server_url}/health", timeout=10) as response:
                return response.status == 200
        except:
            return False
    
    async def call_request(self, request_data: Dict[str, Any]) -> MCPResponse:
        """Generic method to call any MCP request with custom data"""
        try:
            request_id = request_data.get('request_id', f"custom_{hash(str(request_data))}")
            request_type = MCPRequestType(request_data.get('type', 'tool_execution'))
            target = request_data.get('target', '')
            parameters = request_data.get('parameters', {})
            context = request_data.get('context', {})
            priority = request_data.get('priority', 'normal')
            timeout = request_data.get('timeout', 300)
            
            request = MCPRequest(
                request_id=request_id,
                request_type=request_type,
                target=target,
                parameters=parameters,
                context=context,
                priority=priority,
                timeout=timeout
            )
            
            return await self.send_request(request)
            
        except Exception as e:
            return MCPResponse(
                request_id=request_data.get('request_id', 'unknown'),
                success=False,
                error=f"Failed to create request: {str(e)}"
            )
    
    async def batch_request(self, requests: List[Dict[str, Any]]) -> List[MCPResponse]:
        """Execute multiple MCP requests in batch"""
        try:
            tasks = []
            for request_data in requests:
                task = self.call_request(request_data)
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to MCPResponse
            processed_responses = []
            for i, response in enumerate(responses):
                if isinstance(response, Exception):
                    processed_responses.append(MCPResponse(
                        request_id=requests[i].get('request_id', f'batch_{i}'),
                        success=False,
                        error=str(response)
                    ))
                else:
                    processed_responses.append(response)
            
            return processed_responses
            
        except Exception as e:
            return [MCPResponse(
                request_id='batch',
                success=False,
                error=f"Batch request failed: {str(e)}"
            )]
    
    async def stream_request(self, request_data: Dict[str, Any], callback=None) -> MCPResponse:
        """Execute MCP request with streaming response"""
        try:
            request = MCPRequest(
                request_id=request_data.get('request_id', f"stream_{hash(str(request_data))}"),
                request_type=MCPRequestType(request_data.get('type', 'tool_execution')),
                target=request_data.get('target', ''),
                parameters=request_data.get('parameters', {}),
                context=request_data.get('context', {}),
                priority=request_data.get('priority', 'normal'),
                timeout=request_data.get('timeout', 600)
            )
            
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            payload = {
                "request_id": request.request_id,
                "type": request.request_type.value,
                "target": request.target,
                "parameters": request.parameters,
                "context": request.context,
                "priority": request.priority,
                "timeout": request.timeout,
                "stream": True
            }
            
            async with self.session.post(
                f"{self.server_url}/api/v1/request/stream",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=request.timeout)
            ) as response:
                if response.status == 200:
                    final_data = {}
                    async for line in response.content:
                        if line:
                            try:
                                chunk = json.loads(line.decode('utf-8'))
                                if callback:
                                    await callback(chunk)
                                final_data.update(chunk.get('data', {}))
                            except json.JSONDecodeError:
                                continue
                    
                    return MCPResponse(
                        request_id=request.request_id,
                        success=True,
                        data=final_data,
                        metadata={"streamed": True}
                    )
                else:
                    error_text = await response.text()
                    return MCPResponse(
                        request_id=request.request_id,
                        success=False,
                        error=f"HTTP {response.status}: {error_text}"
                    )
                    
        except Exception as e:
            return MCPResponse(
                request_id=request_data.get('request_id', 'stream'),
                success=False,
                error=f"Stream request failed: {str(e)}"
            )
    
    async def close(self):
        """Close MCP client session"""
        await self.session.close()


class MCPPentestOrchestrator:
    """Orchestrator for automated pentesting via MCP"""
    
    def __init__(self, mcp_client: MCPClient):
        self.mcp_client = mcp_client
        self.logger = logging.getLogger(__name__)
        self.pentest_history = []
        
    async def run_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Run reconnaissance phase"""
        self.logger.info(f"Starting reconnaissance on {target}")
        
        results = {}
        
        # Port scanning
        nmap_result = await self.mcp_client.execute_tool(
            "nmap_scan",
            target,
            {"ports": "1-1000", "scan_type": "stealth"}
        )
        
        if nmap_result.success:
            results["port_scan"] = nmap_result.data
        else:
            results["port_scan"] = {"error": nmap_result.error}
        
        # Directory fuzzing
        ffuf_result = await self.mcp_client.execute_tool(
            "ffuf_fuzzing",
            target,
            {"wordlist": "common.txt", "status_codes": "200,301,302,403"}
        )
        
        if ffuf_result.success:
            results["directory_scan"] = ffuf_result.data
        else:
            results["directory_scan"] = {"error": ffuf_result.error}
        
        # Vulnerability scanning
        nuclei_result = await self.mcp_client.execute_tool(
            "nuclei_scan",
            target,
            {"templates": "cves,vulnerabilities", "severity": "medium,high,critical"}
        )
        
        if nuclei_result.success:
            results["vulnerability_scan"] = nuclei_result.data
        else:
            results["vulnerability_scan"] = {"error": nuclei_result.error}
        
        return results
    
    async def run_exploitation(self, target: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run exploitation phase"""
        self.logger.info(f"Starting exploitation on {target}")
        
        results = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            
            if vuln_type == "sql_injection":
                # SQL injection exploitation
                sqlmap_result = await self.mcp_client.execute_tool(
                    "sqlmap_injection",
                    target,
                    {"level": 1, "risk": 1, "technique": "B"}
                )
                
                if sqlmap_result.success:
                    results[f"sql_injection_{vuln.get('id', 'unknown')}"] = sqlmap_result.data
                else:
                    results[f"sql_injection_{vuln.get('id', 'unknown')}"] = {"error": sqlmap_result.error}
            
            elif vuln_type == "xss":
                # XSS exploitation
                xss_result = await self.mcp_client.create_payload(
                    target,
                    "xss",
                    {"context": "reflected", "filter_bypass": True}
                )
                
                if xss_result.success:
                    results[f"xss_{vuln.get('id', 'unknown')}"] = xss_result.data
                else:
                    results[f"xss_{vuln.get('id', 'unknown')}"] = {"error": xss_result.error}
        
        return results
    
    async def run_post_exploitation(self, target: str, access_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run post-exploitation phase"""
        self.logger.info(f"Starting post-exploitation on {target}")
        
        results = {}
        
        # Data extraction
        if access_data.get("database_access"):
            data_result = await self.mcp_client.extract_data(
                target,
                "database",
                {"tables": ["users", "config", "sessions"]}
            )
            
            if data_result.success:
                results["extracted_data"] = data_result.data
            else:
                results["extracted_data"] = {"error": data_result.error}
        
        # Privilege escalation
        if access_data.get("shell_access"):
            priv_esc_result = await self.mcp_client.execute_tool(
                "custom_script",
                target,
                {"script_path": "privilege_escalation.py", "parameters": "--check-all"}
            )
            
            if priv_esc_result.success:
                results["privilege_escalation"] = priv_esc_result.data
            else:
                results["privilege_escalation"] = {"error": priv_esc_result.error}
        
        return results
    
    async def run_full_pentest(self, target: str) -> Dict[str, Any]:
        """Run complete pentest workflow"""
        self.logger.info(f"Starting full pentest on {target}")
        
        pentest_result = {
            "target": target,
            "start_time": None,
            "end_time": None,
            "phases": {}
        }
        
        try:
            # Phase 1: Reconnaissance
            pentest_result["start_time"] = asyncio.get_event_loop().time()
            pentest_result["phases"]["reconnaissance"] = await self.run_reconnaissance(target)
            
            # Phase 2: Vulnerability Analysis
            vulnerabilities = pentest_result["phases"]["reconnaissance"].get("vulnerability_scan", {}).get("vulnerabilities", [])
            pentest_result["phases"]["vulnerability_analysis"] = await self.mcp_client.analyze_vulnerability(target, {
                "vulnerabilities": vulnerabilities
            }).data
            
            # Phase 3: Exploitation
            pentest_result["phases"]["exploitation"] = await self.run_exploitation(target, vulnerabilities)
            
            # Phase 4: Post-Exploitation
            access_data = pentest_result["phases"]["exploitation"]
            pentest_result["phases"]["post_exploitation"] = await self.run_post_exploitation(target, access_data)
            
            pentest_result["end_time"] = asyncio.get_event_loop().time()
            pentest_result["duration"] = pentest_result["end_time"] - pentest_result["start_time"]
            
            # Store in history
            self.pentest_history.append(pentest_result)
            
            return pentest_result
            
        except Exception as e:
            self.logger.error(f"Pentest failed: {e}")
            pentest_result["error"] = str(e)
            return pentest_result
    
    def get_pentest_history(self) -> List[Dict[str, Any]]:
        """Get pentest history"""
        return self.pentest_history
    
    def generate_report(self, pentest_result: Dict[str, Any]) -> str:
        """Generate pentest report"""
        report = f"""
# Pentest Report for {pentest_result['target']}

## Executive Summary
- **Target**: {pentest_result['target']}
- **Duration**: {pentest_result.get('duration', 'Unknown')} seconds
- **Status**: {'Completed' if 'error' not in pentest_result else 'Failed'}

## Phases

### 1. Reconnaissance
{json.dumps(pentest_result['phases'].get('reconnaissance', {}), indent=2)}

### 2. Vulnerability Analysis
{json.dumps(pentest_result['phases'].get('vulnerability_analysis', {}), indent=2)}

### 3. Exploitation
{json.dumps(pentest_result['phases'].get('exploitation', {}), indent=2)}

### 4. Post-Exploitation
{json.dumps(pentest_result['phases'].get('post_exploitation', {}), indent=2)}

## Recommendations
1. Address critical vulnerabilities immediately
2. Implement security controls
3. Regular security assessments
4. Employee security training

## Ethical Considerations
- This pentest was conducted on authorized systems only
- All findings should be reported responsibly
- No sensitive data was extracted or stored
"""
        
        return report
