"""
FastAPI application with advanced security testing capabilities
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import time
import random

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from app.core.config import settings
from app.core.security import is_allowed_domain
from app.chat.chat_manager import ChatManager
from app.security.intent_router import IntentRouter
from app.security.payload_generator import PayloadGenerator
from app.security.exploitation_script_generator import ExploitationScriptGenerator, ExploitationContext, ScriptType, TargetType
from app.security.mcp_client import MCPClient, MCPPentestOrchestrator, MCPRequest, MCPRequestType
from app.security.ai_agent import AutonomousPentestAgent, AgentState, DecisionType
from app.security.threat_intelligence import ThreatIntelligenceService, ThreatLevel
from app.security.advanced_reporting import AdvancedReportingService, ReportType, RiskCategory
from app.security.multi_target_orchestrator import MultiTargetOrchestrator, TargetConfig, OrchestrationMode
from app.security.zap_client import ZAPClient

# Add new imports for advanced features
from app.security.advanced_ai_agent import MultiAgentOrchestrator, AdvancedAgent, AgentRole, AgentCapability
from app.security.zero_day_exploitation import ZeroDayExploitationService
from app.security.red_team_operations import RedTeamOperationsService
from app.security.advanced_reporting_analytics import AdvancedReportingAnalyticsService
from app.security.advanced_web_pentesting import AdvancedWebPentesting, WAFType, AuthBypassType, APISecurityTest
from app.security.ai_payload_generator import AIPayloadGenerator, PayloadRequest, PayloadContext

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Advanced Security Testing Assistant",
    description="Intelligent AI-powered web application security testing platform",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
chat_manager = ChatManager()
intent_router = IntentRouter()
payload_generator = PayloadGenerator()
exploitation_generator = ExploitationScriptGenerator()

# Initialize MCP client if enabled
mcp_client = None
mcp_orchestrator = None
if settings.mcp_enabled:
    mcp_client = MCPClient(settings.mcp_server_url, settings.mcp_api_key)
    mcp_orchestrator = MCPPentestOrchestrator(mcp_client)

# Initialize advanced components
ai_agent = AutonomousPentestAgent()
threat_intelligence = ThreatIntelligenceService()
advanced_reporting = AdvancedReportingService()
multi_target_orchestrator = MultiTargetOrchestrator()

# Initialize advanced services
multi_agent_orchestrator = MultiAgentOrchestrator()
zero_day_service = ZeroDayExploitationService()
red_team_service = RedTeamOperationsService()
advanced_reporting_service = AdvancedReportingAnalyticsService()
advanced_web_pentesting = AdvancedWebPentesting()

# Initialize AI Payload Generator
ai_payload_generator = AIPayloadGenerator()

# Pydantic models for new endpoints
class ExploitationScriptRequest(BaseModel):
    target_url: str
    vulnerability_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    interactive_mode: bool = False

class ExploitationScriptResponse(BaseModel):
    script_content: str
    verification_script: str
    cleanup_script: str
    instructions: str
    ethical_warnings: str
    success: bool = True

class MCPRequestModel(BaseModel):
    target: str
    request_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)

class MCPResponseModel(BaseModel):
    success: bool
    result: Dict[str, Any]
    message: str

class PentestRequest(BaseModel):
    target_url: str
    phases: List[str] = Field(default_factory=lambda: ["reconnaissance", "exploitation"])
    max_duration: int = 3600
    safety_level: str = "medium"

class PentestResponse(BaseModel):
    pentest_id: str
    status: str
    message: str

class AIAgentRequest(BaseModel):
    target_url: str
    max_duration: int = 3600
    safety_level: str = "medium"
    autonomous_mode: bool = True

class AIAgentResponse(BaseModel):
    session_id: str
    status: str
    message: str

class ThreatAnalysisRequest(BaseModel):
    target_url: str
    include_cve_search: bool = True
    include_threat_feeds: bool = True

class ThreatAnalysisResponse(BaseModel):
    report_id: str
    risk_score: float
    threat_indicators: List[Dict[str, Any]]
    recommendations: List[str]
    success: bool = True

class ExecutiveDashboardRequest(BaseModel):
    target_url: str
    vulnerabilities: List[Dict[str, Any]]
    include_trends: bool = False
    historical_data: Optional[List[Dict[str, Any]]] = None

class ExecutiveDashboardResponse(BaseModel):
    dashboard_id: str
    overall_risk_score: float
    risk_level: str
    key_metrics: Dict[str, Any]
    top_vulnerabilities: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    recommendations: List[str]
    charts_data: Dict[str, Any]
    success: bool = True

class MultiTargetRequest(BaseModel):
    targets: List[Dict[str, Any]]  # List of target configurations
    orchestration_mode: str = "parallel"
    max_concurrent_scans: int = 5

class MultiTargetResponse(BaseModel):
    session_id: str
    status: str
    message: str
    total_targets: int

# New Pydantic models for advanced features
class MultiAgentRequest(BaseModel):
    target_url: str
    agent_configs: List[Dict[str, Any]]
    collaboration_mode: str = "coordinated"

class MultiAgentResponse(BaseModel):
    session_id: str
    status: str
    message: str
    agent_status: Dict[str, Any]

class ZeroDayRequest(BaseModel):
    target_url: str
    fuzzing_types: List[str] = ["parameter_fuzzing", "path_fuzzing"]
    max_payloads: int = 100

class ZeroDayResponse(BaseModel):
    discovery_id: str
    status: str
    vulnerabilities_found: int
    exploit_chains_built: int
    results: Dict[str, Any]

class RedTeamRequest(BaseModel):
    target_organization: str
    objectives: List[str]
    operation_scope: str = "comprehensive"

class RedTeamResponse(BaseModel):
    operation_id: str
    status: str
    phases_completed: List[str]
    overall_success: bool
    results: Dict[str, Any]

class AdvancedAnalyticsRequest(BaseModel):
    target_system: str
    analysis_types: List[str] = ["trend_analysis", "anomaly_detection"]
    historical_data: Optional[List[Dict[str, Any]]] = None

class AdvancedAnalyticsResponse(BaseModel):
    analysis_id: str
    status: str
    results: Dict[str, Any]
    recommendations: List[str]

# Advanced Web Pentesting Models
class WAFBypassRequest(BaseModel):
    target_url: str
    waf_type: Optional[str] = None
    encoding_methods: List[str] = Field(default_factory=lambda: ["url", "html", "hex"])

class WAFBypassResponse(BaseModel):
    waf_detected: str
    bypass_results: List[Dict[str, Any]]
    successful_bypasses: int
    recommendations: List[str]
    success: bool = True

class AuthBypassRequest(BaseModel):
    target_url: str
    login_endpoint: Optional[str] = None
    injection_points: List[str] = Field(default_factory=lambda: ["username", "email", "user"])

class AuthBypassResponse(BaseModel):
    bypass_results: List[Dict[str, Any]]
    successful_bypasses: int
    risk_level: str
    recommendations: List[str]
    success: bool = True

class APISecurityRequest(BaseModel):
    api_endpoint: str
    method: str = "GET"
    test_types: List[str] = Field(default_factory=lambda: ["input_validation", "authentication", "authorization"])

class APISecurityResponse(BaseModel):
    test_results: Dict[str, List[Dict[str, Any]]]
    vulnerabilities_found: int
    risk_assessment: str
    recommendations: List[str]
    success: bool = True

class ClientSideSecurityRequest(BaseModel):
    target_url: str
    test_types: List[str] = Field(default_factory=lambda: ["xss", "csp", "javascript"])

class ClientSideSecurityResponse(BaseModel):
    test_results: Dict[str, Any]
    vulnerabilities_found: int
    risk_level: str
    recommendations: List[str]
    success: bool = True

class ComprehensiveWebPentestRequest(BaseModel):
    target_url: str
    include_waf_bypass: bool = True
    include_auth_bypass: bool = True
    include_api_security: bool = True
    include_client_side: bool = True
    include_exploitation_chain: bool = True

class ComprehensiveWebPentestResponse(BaseModel):
    pentest_results: Dict[str, Any]
    summary: Dict[str, Any]
    exploitation_chain: Optional[Dict[str, Any]]
    recommendations: List[str]
    success: bool = True

# AI Payload Generation Models
class AIPayloadRequest(BaseModel):
    target_url: str
    vulnerability_type: str
    context: str = "url_parameter"
    input_field: Optional[str] = None
    current_value: Optional[str] = None
    custom_requirements: Optional[str] = None
    difficulty_level: str = "medium"
    bypass_techniques: Optional[List[str]] = None

class ContextualPayloadRequest(BaseModel):
    target_url: str
    context: str
    vulnerability_type: str = "xss"

class ChainPayloadRequest(BaseModel):
    target_url: str
    vulnerability_chain: List[str]

class BypassPayloadRequest(BaseModel):
    original_payload: str
    bypass_techniques: List[str]

# Background tasks
async def run_ai_agent_session(session_id: str, target_url: str, max_duration: int, safety_level: str):
    """Background task for AI agent session"""
    try:
        # The AI agent runs autonomously
        logger.info(f"AI Agent session {session_id} started for {target_url}")
    except Exception as e:
        logger.error(f"Error in AI agent session {session_id}: {e}")

async def run_pentest_session(pentest_id: str, target_url: str, phases: List[str], max_duration: int, safety_level: str):
    """Background task for pentest session"""
    try:
        if mcp_orchestrator:
            result = await mcp_orchestrator.run_full_pentest(target_url)
            logger.info(f"Pentest session {pentest_id} completed: {result}")
        else:
            logger.warning(f"MCP orchestrator not available for pentest session {pentest_id}")
    except Exception as e:
        logger.error(f"Error in pentest session {pentest_id}: {e}")

# API Endpoints

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Advanced Security Testing Assistant API",
        "version": "2.0.0",
        "status": "operational",
        "features": [
            "AI Agent Autonomous Pentesting",
            "Threat Intelligence Integration",
            "Advanced Reporting & Analytics",
            "Multi-Target Orchestration",
            "MCP Integration",
            "Exploitation Script Generation"
        ]
    }

@app.post("/chat", response_model=Dict[str, Any])
async def chat_endpoint(request: Dict[str, Any]):
    """Chat with the security assistant"""
    try:
        user_message = request.get("message", "")
        if not user_message:
            raise HTTPException(status_code=400, detail="Message is required")
        
        # Route intent and generate response
        intent = intent_router.route_intent(user_message)
        response = await chat_manager.process_message(user_message, intent)
        
        return response
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/payload/generate", response_model=Dict[str, Any])
async def generate_payload(request: Dict[str, Any]):
    """Generate security testing payloads"""
    try:
        vulnerability_type = request.get("vulnerability_type", "")
        target_url = request.get("target_url", "")
        
        if not vulnerability_type or not target_url:
            raise HTTPException(status_code=400, detail="Vulnerability type and target URL are required")
        
        if not is_allowed_domain(target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        payloads = payload_generator.generate_payloads(vulnerability_type, target_url)
        return {"payloads": payloads, "success": True}
    except Exception as e:
        logger.error(f"Error generating payloads: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/exploitation/script", response_model=ExploitationScriptResponse)
async def generate_exploitation_script(request: ExploitationScriptRequest):
    """Generate complete exploitation script"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        context = ExploitationContext(
            target_url=request.target_url,
            target_type=TargetType.WEB_APPLICATION,
            vulnerability_type=ScriptType(request.vulnerability_type),
            parameters=request.parameters,
            user_input=request.target_url
        )
        
        if request.interactive_mode:
            result = exploitation_generator.interactive_mode(context)
        else:
            result = exploitation_generator.generate_script(context)
        
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        
        return ExploitationScriptResponse(**result)
    except Exception as e:
        logger.error(f"Error generating exploitation script: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mcp/request", response_model=MCPResponseModel)
async def send_mcp_request(request: MCPRequestModel):
    """Send request to MCP server"""
    try:
        if not mcp_client:
            raise HTTPException(status_code=503, detail="MCP client not available")
        
        mcp_request = MCPRequest(
            request_id=f"mcp_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            request_type=MCPRequestType(request.request_type),
            target=request.target,
            parameters=request.parameters,
            context=request.context
        )
        
        response = await mcp_client.send_request(mcp_request)
        return MCPResponseModel(
            success=response.success,
            result=response.result,
            message=response.message
        )
    except Exception as e:
        logger.error(f"Error sending MCP request: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/mcp/tools", response_model=Dict[str, Any])
async def list_mcp_tools():
    """List available MCP tools"""
    try:
        if not mcp_client:
            raise HTTPException(status_code=503, detail="MCP client not available")
        
        tools = mcp_client.available_tools
        return {"tools": tools, "success": True}
    except Exception as e:
        logger.error(f"Error listing MCP tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/mcp/status", response_model=Dict[str, Any])
async def check_mcp_status():
    """Check MCP server status"""
    try:
        if not mcp_client:
            return {"status": "disabled", "message": "MCP client not configured"}
        
        status = await mcp_client.check_server_status()
        return {"status": "operational" if status else "unavailable", "success": True}
    except Exception as e:
        logger.error(f"Error checking MCP status: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/pentest/execute", response_model=PentestResponse)
async def start_automated_pentest(request: PentestRequest, background_tasks: BackgroundTasks):
    """Start automated pentest"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        pentest_id = f"pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Add background task
        background_tasks.add_task(
            run_pentest_session,
            pentest_id,
            request.target_url,
            request.phases,
            request.max_duration,
            request.safety_level
        )
        
        return PentestResponse(
            pentest_id=pentest_id,
            status="started",
            message="Automated pentest started successfully"
        )
    except Exception as e:
        logger.error(f"Error starting pentest: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/pentest/{pentest_id}/status", response_model=Dict[str, Any])
async def get_pentest_status(pentest_id: str):
    """Get pentest status"""
    try:
        # This would typically query a database or cache
        return {
            "pentest_id": pentest_id,
            "status": "running",
            "progress": 0.5,
            "message": "Pentest in progress"
        }
    except Exception as e:
        logger.error(f"Error getting pentest status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/pentest/history", response_model=List[Dict[str, Any]])
async def get_pentest_history():
    """Get pentest history"""
    try:
        # This would typically query a database
        return [
            {
                "pentest_id": "pentest_20231201_120000",
                "target_url": "https://example.com",
                "status": "completed",
                "start_time": "2023-12-01T12:00:00",
                "end_time": "2023-12-01T13:00:00"
            }
        ]
    except Exception as e:
        logger.error(f"Error getting pentest history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# AI Agent endpoints
@app.post("/ai-agent/start", response_model=AIAgentResponse)
async def start_ai_agent(request: AIAgentRequest, background_tasks: BackgroundTasks):
    """Start AI agent autonomous pentest"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        session_id = await ai_agent.start_autonomous_pentest(
            request.target_url,
            request.max_duration,
            request.safety_level
        )
        
        # Add background task for monitoring
        background_tasks.add_task(
            run_ai_agent_session,
            session_id,
            request.target_url,
            request.max_duration,
            request.safety_level
        )
        
        return AIAgentResponse(
            session_id=session_id,
            status="started",
            message="AI Agent autonomous pentest started successfully"
        )
    except Exception as e:
        logger.error(f"Error starting AI agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ai-agent/{session_id}/status", response_model=Dict[str, Any])
async def get_ai_agent_status(session_id: str):
    """Get AI agent session status"""
    try:
        status = ai_agent.get_session_status(session_id)
        if not status:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return status
    except Exception as e:
        logger.error(f"Error getting AI agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ai-agent/sessions", response_model=List[Dict[str, Any]])
async def get_all_ai_agent_sessions():
    """Get all AI agent sessions"""
    try:
        return ai_agent.get_all_sessions()
    except Exception as e:
        logger.error(f"Error getting AI agent sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ai-agent/autonomous-mode", response_model=Dict[str, Any])
async def set_autonomous_mode(request: Dict[str, bool]):
    """Set AI agent autonomous mode"""
    try:
        enabled = request.get("enabled", True)
        ai_agent.set_autonomous_mode(enabled)
        return {"success": True, "autonomous_mode": enabled}
    except Exception as e:
        logger.error(f"Error setting autonomous mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Threat Intelligence endpoints
@app.post("/threat-intelligence/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threats(request: ThreatAnalysisRequest):
    """Analyze target for threats"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        threat_report = await threat_intelligence.analyze_target(request.target_url)
        
        if not threat_report:
            raise HTTPException(status_code=500, detail="Failed to analyze threats")
        
        return ThreatAnalysisResponse(
            report_id=threat_report.report_id,
            risk_score=threat_report.risk_score,
            threat_indicators=[{
                "indicator_type": ind.indicator_type,
                "value": ind.value,
                "threat_level": ind.threat_level.value,
                "confidence": ind.confidence,
                "tags": ind.tags
            } for ind in threat_report.threat_indicators],
            recommendations=threat_report.recommendations
        )
    except Exception as e:
        logger.error(f"Error analyzing threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Advanced Reporting endpoints
@app.post("/reporting/executive-dashboard", response_model=ExecutiveDashboardResponse)
async def generate_executive_dashboard(request: ExecutiveDashboardRequest):
    """Generate executive dashboard"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        dashboard = await advanced_reporting.generate_executive_dashboard(
            request.vulnerabilities,
            request.target_url,
            request.historical_data
        )
        
        if not dashboard:
            raise HTTPException(status_code=500, detail="Failed to generate dashboard")
        
        return ExecutiveDashboardResponse(
            dashboard_id=dashboard.dashboard_id,
            overall_risk_score=dashboard.overall_risk_score,
            risk_level=dashboard.risk_level,
            key_metrics=dashboard.key_metrics,
            top_vulnerabilities=dashboard.top_vulnerabilities,
            compliance_status=dashboard.compliance_status,
            recommendations=dashboard.recommendations,
            charts_data=dashboard.charts_data
        )
    except Exception as e:
        logger.error(f"Error generating executive dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Multi-Target Orchestration endpoints
@app.post("/orchestration/start", response_model=MultiTargetResponse)
async def start_multi_target_orchestration(request: MultiTargetRequest):
    """Start multi-target orchestration"""
    try:
        # Validate targets
        target_configs = []
        for target_data in request.targets:
            target_url = target_data.get("url", "")
            if not is_allowed_domain(target_url):
                raise HTTPException(status_code=400, detail=f"Target domain not allowed: {target_url}")
            
            target_config = TargetConfig(
                url=target_url,
                priority=target_data.get("priority", 1),
                max_duration=target_data.get("max_duration", 3600),
                safety_level=target_data.get("safety_level", "medium"),
                scan_types=target_data.get("scan_types", ["vulnerability", "threat_intelligence"]),
                custom_headers=target_data.get("custom_headers", {}),
                authentication=target_data.get("authentication"),
                scope=target_data.get("scope", [])
            )
            target_configs.append(target_config)
        
        # Start orchestration
        mode = OrchestrationMode(request.orchestration_mode)
        session_id = await multi_target_orchestrator.start_orchestration_session(
            target_configs,
            mode
        )
        
        if not session_id:
            raise HTTPException(status_code=500, detail="Failed to start orchestration")
        
        return MultiTargetResponse(
            session_id=session_id,
            status="started",
            message="Multi-target orchestration started successfully",
            total_targets=len(target_configs)
        )
    except Exception as e:
        logger.error(f"Error starting multi-target orchestration: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/orchestration/{session_id}/status", response_model=Dict[str, Any])
async def get_orchestration_status(session_id: str):
    """Get orchestration session status"""
    try:
        session = multi_target_orchestrator.get_session_status(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {
            "session_id": session.session_id,
            "mode": session.mode.value,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "total_targets": session.total_targets,
            "completed_targets": session.completed_targets,
            "failed_targets": session.failed_targets,
            "overall_progress": session.overall_progress,
            "target_statuses": {
                target_id: {
                    "url": status.url,
                    "status": status.status.value,
                    "progress": status.progress,
                    "current_phase": status.current_phase
                }
                for target_id, status in session.status.items()
            }
        }
    except Exception as e:
        logger.error(f"Error getting orchestration status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/orchestration/sessions", response_model=List[Dict[str, Any]])
async def get_all_orchestration_sessions():
    """Get all orchestration sessions"""
    try:
        sessions = multi_target_orchestrator.get_all_sessions()
        return [
            {
                "session_id": session.session_id,
                "mode": session.mode.value,
                "start_time": session.start_time.isoformat(),
                "end_time": session.end_time.isoformat() if session.end_time else None,
                "total_targets": session.total_targets,
                "completed_targets": session.completed_targets,
                "failed_targets": session.failed_targets,
                "overall_progress": session.overall_progress
            }
            for session in sessions.values()
        ]
    except Exception as e:
        logger.error(f"Error getting orchestration sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/orchestration/{session_id}/stop", response_model=Dict[str, Any])
async def stop_orchestration_session(session_id: str):
    """Stop orchestration session"""
    try:
        success = multi_target_orchestrator.stop_session(session_id)
        if not success:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {"success": True, "message": "Orchestration session stopped"}
    except Exception as e:
        logger.error(f"Error stopping orchestration session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/orchestration/load-balancer/status", response_model=Dict[str, Any])
async def get_load_balancer_status():
    """Get load balancer status"""
    try:
        return multi_target_orchestrator.get_load_balancer_status()
    except Exception as e:
        logger.error(f"Error getting load balancer status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# New API endpoints for advanced features

@app.post("/multi-agent/start", response_model=MultiAgentResponse)
async def start_multi_agent_pentest(request: MultiAgentRequest, background_tasks: BackgroundTasks):
    """Start multi-agent pentest with collaboration"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")

        # Create agent configurations
        agent_configs = []
        for config in request.agent_configs:
            role = AgentRole(config.get('role', 'reconnaissance'))
            capabilities = AgentCapability(
                role=role,
                skills=config.get('skills', []),
                confidence_level=config.get('confidence_level', 0.7),
                success_rate=config.get('success_rate', 0.6),
                learning_rate=config.get('learning_rate', 0.1)
            )
            agent_configs.append({
                'role': role,
                'capabilities': capabilities
            })

        # Execute multi-agent pentest
        result = await multi_agent_orchestrator.execute_multi_agent_pentest(
            request.target_url, agent_configs
        )

        return MultiAgentResponse(
            session_id=result['session_id'],
            status="started",
            message="Multi-agent pentest started successfully",
            agent_status=multi_agent_orchestrator.get_all_agents_status()
        )
    except Exception as e:
        logger.error(f"Error starting multi-agent pentest: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/multi-agent/{session_id}/status")
async def get_multi_agent_status(session_id: str):
    """Get multi-agent session status"""
    try:
        # Get session status from orchestrator
        session_status = multi_agent_orchestrator.get_agent_status(session_id)
        return {"session_id": session_id, "status": session_status}
    except Exception as e:
        logger.error(f"Error getting multi-agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/zero-day/discover", response_model=ZeroDayResponse)
async def discover_zero_day_vulnerabilities(request: ZeroDayRequest, background_tasks: BackgroundTasks):
    """Discover zero-day vulnerabilities using advanced fuzzing"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")

        # Import fuzzing types
        from app.security.zero_day_exploitation import FuzzingType
        fuzzing_types = [FuzzingType(ft) for ft in request.fuzzing_types]

        # Discover vulnerabilities
        discovery_results = await zero_day_service.discover_zero_day_vulnerabilities(
            request.target_url, fuzzing_types
        )

        return ZeroDayResponse(
            discovery_id=f"discovery_{int(time.time())}",
            status="completed",
            vulnerabilities_found=len(discovery_results['discovered_vulnerabilities']),
            exploit_chains_built=len(discovery_results['exploit_chains']),
            results=discovery_results
        )
    except Exception as e:
        logger.error(f"Error discovering zero-day vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/zero-day/statistics")
async def get_zero_day_statistics():
    """Get zero-day exploitation statistics"""
    try:
        stats = zero_day_service.get_discovery_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting zero-day statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/red-team/execute", response_model=RedTeamResponse)
async def execute_red_team_operation(request: RedTeamRequest, background_tasks: BackgroundTasks):
    """Execute comprehensive red team operation"""
    try:
        # Execute red team operation
        operation_results = await red_team_service.execute_comprehensive_red_team_operation(
            request.target_organization, request.objectives
        )

        return RedTeamResponse(
            operation_id=operation_results['operation_id'],
            status="completed",
            phases_completed=list(operation_results['phases'].keys()),
            overall_success=operation_results['overall_success'],
            results=operation_results
        )
    except Exception as e:
        logger.error(f"Error executing red team operation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/red-team/statistics")
async def get_red_team_statistics():
    """Get red team operations statistics"""
    try:
        stats = red_team_service.get_red_team_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting red team statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analytics/advanced", response_model=AdvancedAnalyticsResponse)
async def perform_advanced_analytics(request: AdvancedAnalyticsRequest):
    """Perform advanced analytics and predictive analysis"""
    try:
        # Generate sample historical data if not provided
        if not request.historical_data:
            request.historical_data = generate_sample_historical_data()

        # Perform predictive analysis
        analysis_results = await advanced_reporting_service.perform_predictive_analysis(
            request.historical_data
        )

        # Create executive dashboard
        dashboard = await advanced_reporting_service.create_executive_dashboard(
            request.target_system
        )

        return AdvancedAnalyticsResponse(
            analysis_id=f"analysis_{int(time.time())}",
            status="completed",
            results={
                'predictive_analysis': analysis_results,
                'executive_dashboard': dashboard
            },
            recommendations=analysis_results.get('trend_analysis', {}).get('recommendations', [])
        )
    except Exception as e:
        logger.error(f"Error performing advanced analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/compliance/assess")
async def assess_compliance_automation(target_system: str, standards: List[str]):
    """Assess compliance against multiple standards"""
    try:
        from app.security.advanced_reporting_analytics import ComplianceStandard
        compliance_standards = [ComplianceStandard(standard) for standard in standards]

        compliance_results = await advanced_reporting_service.assess_compliance_automation(
            target_system, compliance_standards
        )

        return compliance_results
    except Exception as e:
        logger.error(f"Error assessing compliance: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/statistics")
async def get_analytics_statistics():
    """Get advanced analytics statistics"""
    try:
        stats = advanced_reporting_service.get_analytics_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting analytics statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def generate_sample_historical_data() -> List[Dict[str, Any]]:
    """Generate sample historical data for analytics"""
    data = []
    base_date = datetime.now() - timedelta(days=30)
    
    for i in range(30):
        date = base_date + timedelta(days=i)
        data.append({
            'timestamp': date.isoformat(),
            'vulnerability_count': random.randint(10, 50),
            'attack_count': random.randint(1, 20),
            'risk_score': random.uniform(3.0, 8.0),
            'compliance_score': random.uniform(70.0, 95.0),
            'response_time': random.randint(500, 2000),
            'error_rate': random.uniform(0.001, 0.05)
        })
    
    return data

# Advanced Web Pentesting Endpoints

@app.post("/web-pentest/waf-bypass", response_model=WAFBypassResponse)
async def test_waf_bypass(request: WAFBypassRequest):
    """Test WAF bypass techniques"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        async with advanced_web_pentesting as pentest:
            # Detect WAF type
            waf_type = await pentest.detect_waf(request.target_url)
            
            # Test WAF bypass techniques
            bypass_results = await pentest.test_waf_bypass(request.target_url, waf_type)
            
            # Count successful bypasses
            successful_bypasses = sum(1 for result in bypass_results if result.get('bypass_successful'))
            
            # Generate recommendations
            recommendations = []
            if successful_bypasses > 0:
                recommendations.append("Implement stronger WAF rules")
                recommendations.append("Use multiple WAF layers")
                recommendations.append("Monitor for bypass attempts")
            else:
                recommendations.append("WAF appears to be effective")
                recommendations.append("Continue monitoring for new bypass techniques")
            
            return WAFBypassResponse(
                waf_detected=waf_type.value,
                bypass_results=bypass_results,
                successful_bypasses=successful_bypasses,
                recommendations=recommendations
            )
    except Exception as e:
        logger.error(f"Error testing WAF bypass: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/web-pentest/auth-bypass", response_model=AuthBypassResponse)
async def test_auth_bypass(request: AuthBypassRequest):
    """Test authentication bypass techniques"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        async with advanced_web_pentesting as pentest:
            # Test authentication bypass
            bypass_results = await pentest.test_auth_bypass(request.target_url, request.login_endpoint)
            
            # Count successful bypasses
            successful_bypasses = sum(1 for result in bypass_results if result.get('success'))
            
            # Determine risk level
            risk_level = "High" if successful_bypasses > 0 else "Low"
            
            # Generate recommendations
            recommendations = []
            if successful_bypasses > 0:
                recommendations.append("Implement proper input validation")
                recommendations.append("Use parameterized queries")
                recommendations.append("Implement multi-factor authentication")
                recommendations.append("Use secure session management")
            else:
                recommendations.append("Authentication appears secure")
                recommendations.append("Continue regular security testing")
            
            return AuthBypassResponse(
                bypass_results=bypass_results,
                successful_bypasses=successful_bypasses,
                risk_level=risk_level,
                recommendations=recommendations
            )
    except Exception as e:
        logger.error(f"Error testing auth bypass: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/web-pentest/api-security", response_model=APISecurityResponse)
async def test_api_security(request: APISecurityRequest):
    """Test API security vulnerabilities"""
    try:
        if not is_allowed_domain(request.api_endpoint):
            raise HTTPException(status_code=400, detail="API endpoint not allowed")
        
        async with advanced_web_pentesting as pentest:
            # Test API security
            test_results = await pentest.test_api_security(request.api_endpoint, request.method)
            
            # Count vulnerabilities
            vulnerabilities_found = 0
            for test_type, results in test_results.items():
                vulnerabilities_found += len(results)
            
            # Determine risk assessment
            if vulnerabilities_found > 10:
                risk_assessment = "Critical"
            elif vulnerabilities_found > 5:
                risk_assessment = "High"
            elif vulnerabilities_found > 0:
                risk_assessment = "Medium"
            else:
                risk_assessment = "Low"
            
            # Generate recommendations
            recommendations = []
            if vulnerabilities_found > 0:
                recommendations.append("Implement proper API authentication")
                recommendations.append("Add input validation and sanitization")
                recommendations.append("Implement rate limiting")
                recommendations.append("Use HTTPS for all API communications")
            else:
                recommendations.append("API appears secure")
                recommendations.append("Continue regular security testing")
            
            return APISecurityResponse(
                test_results=test_results,
                vulnerabilities_found=vulnerabilities_found,
                risk_assessment=risk_assessment,
                recommendations=recommendations
            )
    except Exception as e:
        logger.error(f"Error testing API security: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/web-pentest/client-side", response_model=ClientSideSecurityResponse)
async def test_client_side_security(request: ClientSideSecurityRequest):
    """Test client-side security vulnerabilities"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        async with advanced_web_pentesting as pentest:
            # Test client-side security
            test_results = await pentest.test_client_side_security(request.target_url)
            
            # Count vulnerabilities
            vulnerabilities_found = len(test_results.get('xss_vulnerabilities', [])) + \
                                  len(test_results.get('csp_bypass', [])) + \
                                  len(test_results.get('javascript_injection', []))
            
            # Determine risk level
            if vulnerabilities_found > 5:
                risk_level = "Critical"
            elif vulnerabilities_found > 2:
                risk_level = "High"
            elif vulnerabilities_found > 0:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            
            # Generate recommendations
            recommendations = []
            if vulnerabilities_found > 0:
                recommendations.append("Implement Content Security Policy")
                recommendations.append("Sanitize all user inputs")
                recommendations.append("Use HTTPS for all communications")
                recommendations.append("Implement proper XSS protection")
            else:
                recommendations.append("Client-side security appears good")
                recommendations.append("Continue regular security testing")
            
            return ClientSideSecurityResponse(
                test_results=test_results,
                vulnerabilities_found=vulnerabilities_found,
                risk_level=risk_level,
                recommendations=recommendations
            )
    except Exception as e:
        logger.error(f"Error testing client-side security: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/web-pentest/comprehensive", response_model=ComprehensiveWebPentestResponse)
async def run_comprehensive_web_pentest(request: ComprehensiveWebPentestRequest):
    """Run comprehensive web application penetration test"""
    try:
        if not is_allowed_domain(request.target_url):
            raise HTTPException(status_code=400, detail="Target domain not allowed")
        
        async with advanced_web_pentesting as pentest:
            # Run comprehensive pentest
            pentest_results = await pentest.run_comprehensive_web_pentest(request.target_url)
            
            # Extract summary and exploitation chain
            summary = pentest_results.get('summary', {})
            exploitation_chain = pentest_results.get('exploitation_chain')
            
            # Generate recommendations based on results
            recommendations = summary.get('recommendations', [])
            if not recommendations:
                recommendations = ["Continue regular security testing", "Monitor for new vulnerabilities"]
            
            return ComprehensiveWebPentestResponse(
                pentest_results=pentest_results,
                summary=summary,
                exploitation_chain=exploitation_chain,
                recommendations=recommendations
            )
    except Exception as e:
        logger.error(f"Error running comprehensive web pentest: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/web-pentest/statistics")
async def get_web_pentest_statistics():
    """Get web pentesting statistics"""
    try:
        # This would typically come from a database
        # For now, return sample statistics
        return {
            "total_pentests": 150,
            "vulnerabilities_found": 450,
            "high_risk_vulns": 120,
            "medium_risk_vulns": 200,
            "low_risk_vulns": 130,
            "waf_bypasses": 25,
            "auth_bypasses": 15,
            "api_vulnerabilities": 80,
            "client_side_vulns": 60,
            "success_rate": 0.85
        }
    except Exception as e:
        logger.error(f"Error getting web pentest statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# AI Payload Generation Endpoints

@app.post("/ai-payloads/generate", response_model=Dict[str, Any])
async def generate_ai_payloads(request: AIPayloadRequest):
    """Generate intelligent payloads using AI analysis"""
    try:
        # Create payload request
        payload_request = PayloadRequest(
            target_url=request.target_url,
            vulnerability_type=request.vulnerability_type,
            context=PayloadContext(request.context),
            input_field=request.input_field,
            current_value=request.current_value,
            custom_requirements=request.custom_requirements,
            difficulty_level=request.difficulty_level,
            bypass_techniques=request.bypass_techniques
        )
        
        # Generate payloads
        generated_payloads = await ai_payload_generator.generate_intelligent_payload(payload_request)
        
        # Convert to serializable format
        payloads_data = []
        for payload in generated_payloads:
            payloads_data.append({
                "payload": payload.payload,
                "description": payload.description,
                "technique": payload.technique,
                "success_probability": payload.success_probability,
                "bypass_methods": payload.bypass_methods,
                "verification_steps": payload.verification_steps,
                "risk_level": payload.risk_level,
                "mitigation": payload.mitigation,
                "ai_reasoning": payload.ai_reasoning
            })
        
        return {
            "success": True,
            "target_url": request.target_url,
            "vulnerability_type": request.vulnerability_type,
            "context": request.context,
            "payloads": payloads_data,
            "total_payloads": len(payloads_data),
            "ai_generated": True
        }
        
    except Exception as e:
        logger.error(f"Error generating AI payloads: {e}")
        return {
            "success": False,
            "error": str(e),
            "payloads": []
        }

@app.post("/ai-payloads/contextual", response_model=Dict[str, Any])
async def generate_contextual_payloads(request: ContextualPayloadRequest):
    """Generate payloads based on specific context"""
    try:
        # Generate contextual payloads
        generated_payloads = await ai_payload_generator.generate_contextual_payloads(
            request.target_url,
            request.context,
            request.vulnerability_type
        )
        
        # Convert to serializable format
        payloads_data = []
        for payload in generated_payloads:
            payloads_data.append({
                "payload": payload.payload,
                "description": payload.description,
                "technique": payload.technique,
                "success_probability": payload.success_probability,
                "bypass_methods": payload.bypass_methods,
                "verification_steps": payload.verification_steps,
                "risk_level": payload.risk_level,
                "mitigation": payload.mitigation,
                "ai_reasoning": payload.ai_reasoning
            })
        
        return {
            "success": True,
            "target_url": request.target_url,
            "context": request.context,
            "vulnerability_type": request.vulnerability_type,
            "payloads": payloads_data,
            "total_payloads": len(payloads_data),
            "context_optimized": True
        }
        
    except Exception as e:
        logger.error(f"Error generating contextual payloads: {e}")
        return {
            "success": False,
            "error": str(e),
            "payloads": []
        }

@app.post("/ai-payloads/chain", response_model=Dict[str, Any])
async def generate_chain_payloads(request: ChainPayloadRequest):
    """Generate payloads for vulnerability chains"""
    try:
        # Generate chain payloads
        chain_payloads = await ai_payload_generator.generate_chain_payloads(
            request.target_url,
            request.vulnerability_chain
        )
        
        # Convert to serializable format
        chain_data = {}
        for vuln_type, payloads in chain_payloads.items():
            payloads_data = []
            for payload in payloads:
                payloads_data.append({
                    "payload": payload.payload,
                    "description": payload.description,
                    "technique": payload.technique,
                    "success_probability": payload.success_probability,
                    "bypass_methods": payload.bypass_methods,
                    "verification_steps": payload.verification_steps,
                    "risk_level": payload.risk_level,
                    "mitigation": payload.mitigation,
                    "ai_reasoning": payload.ai_reasoning
                })
            chain_data[vuln_type] = payloads_data
        
        return {
            "success": True,
            "target_url": request.target_url,
            "vulnerability_chain": request.vulnerability_chain,
            "chain_payloads": chain_data,
            "total_chains": len(request.vulnerability_chain),
            "chain_optimized": True
        }
        
    except Exception as e:
        logger.error(f"Error generating chain payloads: {e}")
        return {
            "success": False,
            "error": str(e),
            "chain_payloads": {}
        }

@app.post("/ai-payloads/bypass", response_model=Dict[str, Any])
async def generate_bypass_payloads(request: BypassPayloadRequest):
    """Generate bypass variations of a payload"""
    try:
        # Generate bypass payloads
        bypass_payloads = ai_payload_generator.generate_bypass_payloads(
            request.original_payload,
            request.bypass_techniques
        )
        
        return {
            "success": True,
            "original_payload": request.original_payload,
            "bypass_techniques": request.bypass_techniques,
            "bypass_payloads": bypass_payloads,
            "total_bypasses": len(bypass_payloads),
            "bypass_generated": True
        }
        
    except Exception as e:
        logger.error(f"Error generating bypass payloads: {e}")
        return {
            "success": False,
            "error": str(e),
            "bypass_payloads": []
        }

@app.get("/ai-payloads/analyze/{target_url:path}")
async def analyze_target_for_payloads(target_url: str):
    """Analyze target for intelligent payload generation"""
    try:
        # Analyze target
        analysis = await ai_payload_generator.analyze_target(target_url)
        
        return {
            "success": True,
            "target_url": target_url,
            "analysis": analysis,
            "recommendations": {
                "vulnerability_types": _get_recommended_vuln_types(analysis),
                "payload_contexts": _get_recommended_contexts(analysis),
                "bypass_techniques": _get_recommended_bypasses(analysis)
            }
        }
        
    except Exception as e:
        logger.error(f"Error analyzing target: {e}")
        return {
            "success": False,
            "error": str(e),
            "analysis": {}
        }

@app.get("/ai-payloads/statistics")
async def get_payload_statistics():
    """Get statistics about payload generation"""
    try:
        stats = ai_payload_generator.get_payload_statistics()
        
        return {
            "success": True,
            "statistics": stats,
            "ai_capabilities": {
                "intelligent_generation": True,
                "context_awareness": True,
                "bypass_techniques": True,
                "chain_generation": True,
                "target_analysis": True
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting payload statistics: {e}")
        return {
            "success": False,
            "error": str(e),
            "statistics": {}
        }

def _get_recommended_vuln_types(analysis: Dict[str, Any]) -> List[str]:
    """Get recommended vulnerability types based on target analysis"""
    recommendations = []
    
    tech_stack = analysis.get("technology_stack", {})
    language = tech_stack.get("language", "").lower()
    
    if "php" in language:
        recommendations.extend(["xss", "sqli", "lfi", "rfi"])
    elif "asp" in language:
        recommendations.extend(["xss", "sqli", "lfi"])
    elif "jsp" in language:
        recommendations.extend(["xss", "sqli", "lfi"])
    
    if analysis.get("waf_detected"):
        recommendations.extend(["xss", "sqli"])
    
    return list(set(recommendations))

def _get_recommended_contexts(analysis: Dict[str, Any]) -> List[str]:
    """Get recommended payload contexts based on target analysis"""
    contexts = ["url_parameter", "form_field"]
    
    if "api" in analysis.get("path", "").lower():
        contexts.extend(["json_body", "xml_body", "header"])
    
    return contexts

def _get_recommended_bypasses(analysis: Dict[str, Any]) -> List[str]:
    """Get recommended bypass techniques based on target analysis"""
    bypasses = ["encoding", "case_manipulation"]
    
    if analysis.get("waf_detected"):
        bypasses.extend(["whitespace", "comment_injection", "null_byte"])
    
    return bypasses

# Health check endpoint
@app.get("/health", response_model=Dict[str, Any])
async def health_check():
    """Health check endpoint"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "components": {
                "chat_manager": "operational",
                "intent_router": "operational",
                "payload_generator": "operational",
                "exploitation_generator": "operational",
                "ai_agent": "operational",
                "threat_intelligence": "operational",
                "advanced_reporting": "operational",
                "multi_target_orchestrator": "operational",
                "advanced_web_pentesting": "operational",
                "multi_agent_orchestrator": "operational",
                "zero_day_service": "operational",
                "red_team_service": "operational",
                "advanced_reporting_service": "operational",
                "ai_payload_generator": "operational"
            }
        }
        
        # Check MCP status if enabled
        if mcp_client:
            try:
                mcp_status = await mcp_client.check_server_status()
                health_status["components"]["mcp_client"] = "operational" if mcp_status else "unavailable"
            except:
                health_status["components"]["mcp_client"] = "error"
        else:
            health_status["components"]["mcp_client"] = "disabled"
        
        return health_status
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

if __name__ == "__main__":
    uvicorn.run(
        "app.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
