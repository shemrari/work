import logging
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.orm import Session
from sqlalchemy import func

from ...models import pydantic_models as models
from ...models import sql_models
from ...services.anomaly_analysis import AnomalyServiceError, analyze_latest_wazuh_alerts
from .. import dependencies

router = APIRouter(prefix="/incidents", tags=["incidents"])
logger = logging.getLogger(__name__)
SIMULATED_SUCCESS = "simulated_success"


def _incident_severity(item: Dict[str, Any]) -> str:
    alert = item["alert"]
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}
    category_text = " ".join(
        [str(group) for group in groups]
        + [str(rule.get("description") or ""), str(decoder.get("name") or "")]
    ).lower()

    try:
        rule_level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        rule_level = 0
    score = float(item.get("anomaly_score") or 0)

    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    candidates = ["low"]
    if rule_level >= 15 or score >= 90:
        candidates.append("critical")
    elif rule_level >= 12 or score >= 75:
        candidates.append("high")
    elif rule_level >= 7 or score >= 50:
        candidates.append("medium")

    if any(term in category_text for term in ("malware", "ransomware", "rootkit", "exploit")):
        candidates.append("critical")
    elif any(term in category_text for term in ("brute force", "bruteforce", "authentication_failed", "vulnerability")):
        candidates.append("high")

    return max(candidates, key=rank.__getitem__)


def _incident_record(item: Dict[str, Any]) -> Dict[str, Any]:
    alert = item["alert"]
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    category = ", ".join(str(group) for group in groups) or "uncategorized"
    rule_id = str(rule.get("id") or "unknown")
    rule_level = rule.get("level")
    source = (
        alert.get("srcip")
        or (alert.get("source", {}).get("ip") if isinstance(alert.get("source"), dict) else None)
        or agent.get("name")
        or agent.get("id")
        or alert.get("location")
        or "unknown"
    )
    alert_reference = alert.get("_id") or alert.get("id")
    timestamp = alert.get("@timestamp") or alert.get("timestamp")
    detected_at = None
    if isinstance(timestamp, str):
        try:
            detected_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            detected_at = None
    if detected_at is None:
        detected_at = datetime.now(timezone.utc)

    description = rule.get("description") or f"Wazuh rule {rule_id} anomaly"
    score = float(item["anomaly_score"])
    return {
        "title": str(description),
        "description": (
            f"Isolation Forest flagged this Wazuh alert with anomaly score {score:.1f}/100. "
            f"Rule {rule_id} (level {rule_level if rule_level is not None else 'unknown'}); "
            f"category {category}."
        ),
        "severity": _incident_severity(item),
        "status": "open",
        "source": str(source),
        "detected_at": detected_at,
        "anomaly_score": score,
        "wazuh_alert_id": str(alert_reference),
        "wazuh_alert": alert,
    }


def _simulated_target(action_type: str, incident: sql_models.Incident) -> str:
    alert = incident.wazuh_alert if isinstance(incident.wazuh_alert, dict) else {}
    if action_type == "block_ip":
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        source = alert.get("source") if isinstance(alert.get("source"), dict) else {}
        candidate = alert.get("srcip") or data.get("srcip") or source.get("ip")
        try:
            return str(ipaddress.ip_address(str(candidate)))
        except ValueError as error:
            raise HTTPException(
                status_code=422,
                detail="This stored Wazuh alert has no valid source IP to simulate blocking.",
            ) from error

    if action_type == "isolate_asset":
        agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        target = agent.get("name") or agent.get("id")
        if target:
            return str(target)
        raise HTTPException(
            status_code=422,
            detail="This stored Wazuh alert has no agent to simulate isolating.",
        )

    if action_type == "notify_admin":
        return f"local-admin:incident-{incident.id}"
    return f"local-report:incident-{incident.id}"


def _simulation_description(action_type: str, target: str) -> str:
    descriptions = {
        "block_ip": f"Simulated block of {target}; no firewall or network command was executed.",
        "isolate_asset": f"Simulated isolation of {target}; no host or network change was made.",
        "notify_admin": "Simulated administrator notification; no message was sent.",
        "create_report": "Simulated local report action; no external file or service was changed.",
    }
    return descriptions[action_type]

@router.get("/", response_model=List[models.IncidentResponse])
def read_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db)):
    incidents = db.query(sql_models.Incident).offset(skip).limit(limit).all()
    return [models.IncidentResponse.model_validate(incident) for incident in incidents]


@router.post("/sync-ai")
async def sync_ai_incidents(
    limit: int = Query(500, ge=1, le=500),
    db: Session = Depends(dependencies.get_db),
) -> Dict[str, Any]:
    try:
        analysis = await analyze_latest_wazuh_alerts(limit)
    except AnomalyServiceError as error:
        logger.error("AI incident synchronization could not load Wazuh alerts: %s", error.detail)
        raise HTTPException(status_code=error.status_code, detail=error.detail) from error
    except Exception as error:
        logger.exception("AI incident synchronization failed during analysis")
        raise HTTPException(status_code=500, detail="Anomaly analysis failed") from error

    anomaly_items = analysis["anomalies"]
    records_by_reference: Dict[str, Dict[str, Any]] = {}
    skipped_missing_reference = 0
    for item in anomaly_items:
        alert = item["alert"]
        if not (alert.get("_id") or alert.get("id")):
            skipped_missing_reference += 1
            continue
        record = _incident_record(item)
        records_by_reference.setdefault(record["wazuh_alert_id"], record)

    references = list(records_by_reference)
    if references:
        existing_references = {
            reference
            for (reference,) in db.query(sql_models.Incident.wazuh_alert_id)
            .filter(sql_models.Incident.wazuh_alert_id.in_(references))
            .all()
        }
        new_records = [
            record
            for reference, record in records_by_reference.items()
            if reference not in existing_references
        ]
    else:
        new_records = []

    created = 0
    if new_records:
        try:
            statement = (
                postgres_insert(sql_models.Incident)
                .values(new_records)
                .on_conflict_do_nothing(index_elements=[sql_models.Incident.wazuh_alert_id])
            )
            result = db.execute(statement)
            db.commit()
            created = result.rowcount or 0
        except Exception as error:
            db.rollback()
            logger.exception("Failed to persist AI-generated incidents")
            raise HTTPException(status_code=500, detail="Failed to persist incidents") from error

    return {
        "analysis_status": analysis["analysis_status"],
        "alerts_analyzed": analysis["summary"]["alerts_analyzed"],
        "anomalies_detected": len(anomaly_items),
        "incidents_created": created,
        "already_synced": max(0, len(records_by_reference) - created),
        "skipped_missing_wazuh_reference": skipped_missing_reference,
        "message": analysis["message"],
    }


@router.get("/response-actions/summary")
def response_action_summary(db: Session = Depends(dependencies.get_db)) -> Dict[str, int]:
    action_model = sql_models.ResponseAction
    total_actions = db.query(func.count(action_model.id)).scalar() or 0
    simulated_blocks = db.query(func.count(action_model.id)).filter(
        action_model.action_type == "block_ip"
    ).scalar() or 0
    notifications = db.query(func.count(action_model.id)).filter(
        action_model.action_type == "notify_admin"
    ).scalar() or 0
    successful_actions = db.query(func.count(action_model.id)).filter(
        action_model.result == SIMULATED_SUCCESS
    ).scalar() or 0
    return {
        "total_actions": total_actions,
        "simulated_blocks": simulated_blocks,
        "notifications": notifications,
        "successful_actions": successful_actions,
    }


@router.post(
    "/{incident_id}/respond",
    response_model=models.SimulatedResponseActionResult,
)
def respond_to_incident(
    incident_id: int,
    action_request: models.ResponseActionCreate,
    db: Session = Depends(dependencies.get_db),
):
    incident = db.query(sql_models.Incident).filter(sql_models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_type = action_request.action_type
    target = _simulated_target(action_type, incident)
    description = _simulation_description(action_type, target)
    action_values = {
        "incident_id": incident_id,
        "action_type": action_type,
        "target": target,
        "status": "simulated",
        "description": description,
        "executed_at": datetime.now(timezone.utc),
        "result": SIMULATED_SUCCESS,
    }

    try:
        statement = (
            postgres_insert(sql_models.ResponseAction)
            .values(action_values)
            .on_conflict_do_nothing(constraint="uq_response_action_incident_type")
            .returning(sql_models.ResponseAction.id)
        )
        inserted_id = db.execute(statement).scalar_one_or_none()
        db.commit()
    except Exception as error:
        db.rollback()
        logger.exception("Failed to record simulated response action")
        raise HTTPException(status_code=500, detail="Failed to record simulated response action") from error

    action = db.query(sql_models.ResponseAction).filter(
        sql_models.ResponseAction.incident_id == incident_id,
        sql_models.ResponseAction.action_type == action_type,
    ).first()
    if action is None:
        raise HTTPException(status_code=500, detail="Response action record was not available after commit")

    already_executed = inserted_id is None
    return {
        "action": models.ResponseActionResponse.model_validate(action),
        "already_executed": already_executed,
        "message": "This simulated action was already recorded." if already_executed else description,
    }


@router.get(
    "/{incident_id}/timeline",
    response_model=models.IncidentTimelineResponse,
)
def read_incident_timeline(incident_id: int, db: Session = Depends(dependencies.get_db)):
    incident = db.query(sql_models.Incident).filter(sql_models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = (
        db.query(sql_models.ResponseAction)
        .filter(sql_models.ResponseAction.incident_id == incident_id)
        .order_by(sql_models.ResponseAction.executed_at.asc(), sql_models.ResponseAction.id.asc())
        .all()
    )
    return {
        "incident": models.IncidentResponse.model_validate(incident),
        "response_actions": [models.ResponseActionResponse.model_validate(action) for action in actions],
    }

@router.get("/{incident_id}", response_model=models.IncidentResponse)
def read_incident(incident_id: int, db: Session = Depends(dependencies.get_db)):
    incident = db.query(sql_models.Incident).filter(sql_models.Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return models.IncidentResponse.model_validate(incident)

@router.post("/", response_model=models.IncidentResponse)
def create_incident(incident: models.IncidentCreate, db: Session = Depends(dependencies.get_db)):
    db_incident = sql_models.Incident(**incident.dict())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return models.IncidentResponse.model_validate(db_incident)
