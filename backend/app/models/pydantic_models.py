from pydantic import BaseModel
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime

class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    os: str
    zone: str
    status: str
    risk_level: int

class AssetCreate(AssetBase):
    pass

class AssetResponse(AssetBase):
    id: int
    last_activity: Optional[datetime]

    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    source: str
    destination: str
    alert_type: str
    severity: str
    status: str
    ia_score: Optional[int] = None

class AlertCreate(AlertBase):
    pass

class AlertResponse(AlertBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True

class IncidentBase(BaseModel):
    title: str
    description: str
    status: str
    assigned_to: Optional[str] = None

class IncidentCreate(IncidentBase):
    pass

class IncidentResponse(IncidentBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    severity: Optional[str] = None
    source: Optional[str] = None
    detected_at: Optional[datetime] = None
    anomaly_score: Optional[float] = None
    wazuh_alert_id: Optional[str] = None
    wazuh_alert: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class ResponseActionCreate(BaseModel):
    action_type: Literal["block_ip", "isolate_asset", "notify_admin", "create_report"]


class ResponseActionResponse(BaseModel):
    id: int
    incident_id: int
    action_type: str
    target: str
    status: str
    description: str
    executed_at: datetime
    result: str

    class Config:
        from_attributes = True


class IncidentTimelineResponse(BaseModel):
    incident: IncidentResponse
    response_actions: List[ResponseActionResponse]


class SimulatedResponseActionResult(BaseModel):
    action: ResponseActionResponse
    already_executed: bool
    message: str


class SimulationRunResponse(BaseModel):
    id: int
    scenario: str
    target: str
    status: str
    attempt_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: str
    ports_tested: Optional[List[int]] = None
    wazuh_status: str
    wazuh_alert_id: Optional[str] = None
    wazuh_alert: Optional[Dict[str, Any]] = None
    wazuh_rule_id: Optional[str] = None
    wazuh_rule_level: Optional[int] = None
    ai_status: Optional[str] = None
    ai_score: Optional[float] = None
    incident_id: Optional[int] = None
    error: Optional[str] = None

    class Config:
        from_attributes = True


class IncidentReportResponse(BaseModel):
    incident: IncidentResponse
    wazuh_rule_id: Optional[str] = None
    wazuh_rule_level: Optional[int] = None
    wazuh_description: Optional[str] = None
    agent_target: Optional[str] = None
    ai_anomaly_score: Optional[float] = None
    ai_anomaly_status: Optional[str] = None
    response_actions: List[ResponseActionResponse]
    timeline: List[Dict[str, Any]]
    simulations: List[SimulationRunResponse]
    lab_simulation_only: bool = True
    response_actions_simulated: bool = True
    real_system_commands_executed: bool = False

class HealthResponse(BaseModel):
    status: str
    database: str
