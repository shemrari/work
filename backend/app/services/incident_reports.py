from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models import pydantic_models as models
from app.models import sql_models


def _event_time(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else "Unavailable"


def build_incident_report(incident_id: int, db: Session) -> Dict[str, Any]:
    incident = (
        db.query(sql_models.Incident)
        .filter(sql_models.Incident.id == incident_id)
        .first()
    )
    if incident is None:
        raise LookupError("Incident not found")

    actions = (
        db.query(sql_models.ResponseAction)
        .filter(sql_models.ResponseAction.incident_id == incident_id)
        .order_by(sql_models.ResponseAction.executed_at.asc(), sql_models.ResponseAction.id.asc())
        .all()
    )

    simulation_runs = (
        db.query(sql_models.SimulationRun)
        .filter(sql_models.SimulationRun.wazuh_alert_id == incident.wazuh_alert_id)
        .order_by(sql_models.SimulationRun.started_at.asc(), sql_models.SimulationRun.id.asc())
        .all()
        if incident.wazuh_alert_id
        else []
    )

    alert = incident.wazuh_alert if isinstance(incident.wazuh_alert, dict) else {}
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}

    timeline: List[Dict[str, Any]] = []
    if incident.detected_at:
        timeline.append(
            {
                "event": "wazuh_alert_detected",
                "timestamp": _event_time(incident.detected_at),
                "description": "Persisted Wazuh alert was correlated with this incident.",
                "reference": incident.wazuh_alert_id,
            }
        )
    for action in actions:
        timeline.append(
            {
                "event": "response_action_simulated",
                "timestamp": _event_time(action.executed_at),
                "description": action.description,
                "reference": f"response-action-{action.id}",
            }
        )
    for run in simulation_runs:
        timeline.append(
            {
                "event": "lab_simulation",
                "timestamp": _event_time(run.completed_at or run.started_at),
                "description": run.result,
                "reference": f"simulation-run-{run.id}",
            }
        )
    timeline.sort(key=lambda event: event["timestamp"])

    incident_response = models.IncidentResponse.model_validate(incident)
    action_responses = [models.ResponseActionResponse.model_validate(action) for action in actions]
    simulation_responses = [models.SimulationRunResponse.model_validate(run) for run in simulation_runs]

    if incident.anomaly_score is None:
        anomaly_status = "unavailable"
    else:
        anomaly_status = "anomaly"

    return models.IncidentReportResponse(
        incident=incident_response,
        wazuh_rule_id=str(rule["id"]) if rule.get("id") is not None else None,
        wazuh_rule_level=int(rule["level"]) if rule.get("level") is not None else None,
        wazuh_description=str(rule["description"]) if rule.get("description") else None,
        agent_target=str(agent.get("name") or agent.get("id")) if (agent.get("name") or agent.get("id")) else None,
        ai_anomaly_score=incident.anomaly_score,
        ai_anomaly_status=anomaly_status,
        response_actions=action_responses,
        timeline=timeline,
        simulations=simulation_responses,
    ).model_dump()
