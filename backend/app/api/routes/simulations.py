import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.config import settings
from ...models import pydantic_models as models
from ...models import sql_models
from ...services.anomaly_analysis import analyze_latest_wazuh_alerts
from ...services.wazuh_client import wazuh_client
from ...services.wazuh_indexer_client import wazuh_indexer_client
from .. import dependencies

router = APIRouter(prefix="/simulations", tags=["simulations"])
logger = logging.getLogger(__name__)
LAB_AGENT_NAME = "ssh-lab-target"
LAB_TARGET = "ssh-lab-target:22"
PORT_SCAN_TARGET = LAB_AGENT_NAME
PORT_SCAN_PORTS = (22, 80, 443, 8080, 3306)
SSH_SIMULATOR_ATTEMPTS = 10
PORT_SCAN_ATTEMPTS = len(PORT_SCAN_PORTS)
AGENT_REGISTRATION_TIMEOUT = 45
WAZUH_ALERT_POLL_COUNT = 15
WAZUH_ALERT_POLL_INTERVAL = 2
PENDING_ALERT_REFRESH_WINDOW = 180


@router.get("/lab-status")
async def get_lab_status() -> Dict[str, str]:
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.get(f"{settings.attack_simulator_url.rstrip('/')}/health")
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return {"status": "unavailable", "scope": "LAB"}

    if not isinstance(payload, dict) or payload.get("status") != "ok" or payload.get("scope") != "isolated-docker-lab":
        return {"status": "unavailable", "scope": "LAB"}
    return {"status": "healthy", "scope": "LAB"}


def _agent_items(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = response.get("data")
    items = data.get("affected_items", []) if isinstance(data, dict) else []
    return items if isinstance(items, list) else []


async def _wait_for_lab_agent() -> bool:
    deadline = time.monotonic() + AGENT_REGISTRATION_TIMEOUT
    while time.monotonic() < deadline:
        try:
            response = await wazuh_client.get_agents(limit=500, sort="name")
            for agent in _agent_items(response):
                if agent.get("name") == LAB_AGENT_NAME and agent.get("status") == "active":
                    return True
        except Exception as error:
            logger.warning("Could not check lab agent registration: %s", type(error).__name__)
        await asyncio.sleep(2)
    return False


def _is_lab_scenario_alert(alert: Dict[str, Any], started_at: datetime, scenario: str) -> bool:
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    if agent.get("name") != LAB_AGENT_NAME:
        return False

    timestamp = alert.get("@timestamp") or alert.get("timestamp")
    if not isinstance(timestamp, str):
        return False
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
        if parsed_timestamp.astimezone(timezone.utc) < started_at:
            return False
    except ValueError:
        return False

    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    searchable = " ".join([str(group) for group in groups] + [str(rule.get("description") or "")]).lower()
    if scenario == "ssh_brute_force":
        return any(token in searchable for token in ("sshd", "ssh", "authentication_failed", "invalid_login"))
    if scenario == "port_scan":
        return any(token in searchable for token in (
            "port scan", "port_scan", "portscan", "network scan", "network reconnaissance",
            "invalid format", "invalid identification", "did not receive identification string",
        ))
    return False


async def _find_lab_alert(
    started_at: datetime,
    scenario: str,
    poll_count: int = WAZUH_ALERT_POLL_COUNT,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    for poll_number in range(poll_count):
        try:
            response = await wazuh_indexer_client.get_alerts(
                limit=500,
                offset=0,
                sort="-@timestamp",
                agent_name=LAB_AGENT_NAME,
                timestamp_gte=started_at.isoformat(),
            )
        except Exception as error:
            logger.warning("Could not query Wazuh alerts for lab run: %s", type(error).__name__)
            return None, "unavailable"

        data = response.get("data")
        items = data.get("affected_items", []) if isinstance(data, dict) else []
        matches = [
            item for item in items
            if isinstance(item, dict) and _is_lab_scenario_alert(item, started_at, scenario)
        ]
        if matches:
            def rule_level(item: Dict[str, Any]) -> int:
                rule = item.get("rule") if isinstance(item.get("rule"), dict) else {}
                try:
                    return int(rule.get("level") or 0)
                except (TypeError, ValueError):
                    return 0

            matches.sort(key=rule_level, reverse=True)
            return matches[0], "detected"

        if poll_number + 1 < poll_count:
            await asyncio.sleep(WAZUH_ALERT_POLL_INTERVAL)
    return None, "pending"


async def _correlate_alert_with_ai_and_incident(
    db: Session,
    run: sql_models.SimulationRun,
    alert: Dict[str, Any],
) -> None:
    alert_id = str(alert.get("_id") or alert.get("id") or "")
    if not alert_id:
        return

    try:
        analysis = await analyze_latest_wazuh_alerts(limit=500)
        matching = next(
            (
                item for item in analysis.get("results", [])
                if str(item.get("alert", {}).get("_id") or item.get("alert", {}).get("id") or "") == alert_id
            ),
            None,
        )
    except Exception as error:
        logger.warning("AI correlation unavailable for lab alert %s: %s", alert_id, type(error).__name__)
        run.ai_status = "unavailable"
        run.result += " AI correlation is currently unavailable."
        return

    if not matching:
        run.ai_status = "not_found"
        run.result += " The Wazuh alert was not present in the current AI analysis batch."
        return

    run.ai_score = matching.get("anomaly_score")
    if not matching.get("is_anomaly"):
        run.ai_status = "not_anomaly"
        run.result += f" AI analysis did not flag this alert (score {matching.get('anomaly_score')})."
        return

    run.ai_status = "anomaly"
    score = matching.get("anomaly_score")
    run.result += f" AI flagged the alert as an anomaly (score {score})."
    try:
        from .incidents import sync_ai_incidents

        await sync_ai_incidents(limit=500, db=db)
        incident = (
            db.query(sql_models.Incident)
            .filter(sql_models.Incident.wazuh_alert_id == alert_id)
            .first()
        )
        if incident:
            run.incident_id = incident.id
            run.result += f" Correlated incident #{incident.id}."
    except Exception as error:
        logger.warning("Incident synchronization unavailable for lab alert %s: %s", alert_id, type(error).__name__)
        run.result += " Incident synchronization is currently unavailable."


async def _execute_lab_scenario(
    db: Session,
    scenario: str,
    target: str,
    simulator_path: str,
    max_attempts: int,
    expected_ports: Optional[Tuple[int, ...]] = None,
) -> models.SimulationRunResponse:
    active_run = (
        db.query(sql_models.SimulationRun)
        .filter(sql_models.SimulationRun.status == "running")
        .first()
    )
    if active_run:
        raise HTTPException(status_code=409, detail="A lab simulation is already running")

    started_at = datetime.now(timezone.utc)
    run = sql_models.SimulationRun(
        scenario=scenario,
        target=target,
        status="running",
        attempt_count=0,
        started_at=started_at,
        result="Waiting for the enrolled Wazuh lab agent.",
        wazuh_status="pending",
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    if not await _wait_for_lab_agent():
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)
        run.wazuh_status = "unavailable"
        run.result = "Simulation was not started because the Wazuh lab agent is not active."
        run.error = "Wazuh agent ssh-lab-target did not become active before timeout."
        db.commit()
        db.refresh(run)
        raise HTTPException(status_code=503, detail=run.error)

    try:
        async with httpx.AsyncClient(timeout=50) as client:
            response = await client.post(
                f"{settings.attack_simulator_url.rstrip('/')}{simulator_path}",
                json={"run_id": run.id, "scenario": scenario},
            )
            response.raise_for_status()
            simulator_result = response.json()
    except (httpx.HTTPError, ValueError) as error:
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)
        run.result = "The isolated attack-simulator service did not complete the run."
        run.error = type(error).__name__
        db.commit()
        db.refresh(run)
        raise HTTPException(status_code=502, detail=run.error) from error

    attempts_sent = simulator_result.get("attempts_sent")
    if not isinstance(attempts_sent, int) or not 0 <= attempts_sent <= max_attempts:
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)
        run.result = "The simulator returned an invalid attempt count."
        run.error = "Invalid simulator response"
        db.commit()
        db.refresh(run)
        raise HTTPException(status_code=502, detail=run.error)

    if expected_ports is not None:
        returned_ports = simulator_result.get("ports_tested")
        if (
            simulator_result.get("target") != target
            or returned_ports != list(expected_ports)
            or attempts_sent != len(expected_ports)
        ):
            run.status = "failed"
            run.completed_at = datetime.now(timezone.utc)
            run.result = "The simulator returned a target or port list outside the approved lab scope."
            run.error = "Invalid port-scan response"
            db.commit()
            db.refresh(run)
            raise HTTPException(status_code=502, detail=run.error)
        run.ports_tested = returned_ports

    run.attempt_count = attempts_sent
    run.completed_at = datetime.now(timezone.utc)
    run.status = (
        "completed"
        if simulator_result.get("status") in {"completed", "partial"} and attempts_sent > 0
        else "failed"
    )
    run.result = str(simulator_result.get("result") or "No simulator result was returned.")
    run.error = "; ".join(simulator_result.get("connection_errors") or []) or None
    db.commit()

    if attempts_sent > 0:
        alert, detection_status = await _find_lab_alert(started_at, scenario)
        run.wazuh_status = detection_status or "pending"
        if alert:
            run.wazuh_alert_id = str(alert.get("_id") or alert.get("id") or "") or None
            run.wazuh_alert = alert
            rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
            run.wazuh_rule_id = str(rule.get("id")) if rule.get("id") is not None else None
            try:
                run.wazuh_rule_level = int(rule.get("level")) if rule.get("level") is not None else None
            except (TypeError, ValueError):
                run.wazuh_rule_level = None
            run.result += f" Wazuh alert detected: {run.wazuh_alert_id}."
            await _correlate_alert_with_ai_and_incident(db, run, alert)
        elif detection_status == "pending":
            run.wazuh_status = "pending"
            run.ai_status = "pending"
            run.result += " No matching Wazuh event is indexed yet; history will check again."
        else:
            run.ai_status = "unavailable"
            run.result += " Wazuh alert lookup is unavailable; refresh history to check again."
    else:
        run.wazuh_status = "not_detected"
        run.ai_status = "not_analyzed"
        run.result += " No network probe reached the lab target."

    db.commit()
    db.refresh(run)
    return models.SimulationRunResponse.model_validate(run)


@router.get("/", response_model=List[models.SimulationRunResponse])
async def list_simulations(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(dependencies.get_db),
):
    runs = (
        db.query(sql_models.SimulationRun)
        .order_by(sql_models.SimulationRun.started_at.desc(), sql_models.SimulationRun.id.desc())
        .limit(limit)
        .all()
    )
    return [models.SimulationRunResponse.model_validate(run) for run in runs]


@router.post("/refresh-pending", response_model=List[models.SimulationRunResponse])
async def refresh_pending_simulations(db: Session = Depends(dependencies.get_db)):
    runs = (
        db.query(sql_models.SimulationRun)
        .filter(
            sql_models.SimulationRun.status == "completed",
            sql_models.SimulationRun.wazuh_status.in_({"pending", "unavailable", "not_detected"}),
        )
        .order_by(sql_models.SimulationRun.started_at.desc(), sql_models.SimulationRun.id.desc())
        .limit(3)
        .all()
    )
    changed = False
    now = datetime.now(timezone.utc)
    for run in runs:
        if run.completed_at is None:
            continue
        age = (now - run.completed_at).total_seconds()
        if age > PENDING_ALERT_REFRESH_WINDOW and run.wazuh_status == "not_detected":
            continue

        alert, detection_status = await _find_lab_alert(run.started_at, run.scenario, poll_count=1)
        if alert:
            alert_id = str(alert.get("_id") or alert.get("id") or "") or None
            if not alert_id:
                continue
            run.wazuh_status = "detected"
            run.wazuh_alert_id = alert_id
            run.wazuh_alert = alert
            rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
            run.wazuh_rule_id = str(rule.get("id")) if rule.get("id") is not None else None
            try:
                run.wazuh_rule_level = int(rule.get("level")) if rule.get("level") is not None else None
            except (TypeError, ValueError):
                run.wazuh_rule_level = None
            if not run.result.endswith(f"Wazuh alert detected: {alert_id}."):
                run.result += f" Wazuh alert detected: {alert_id}."
            await _correlate_alert_with_ai_and_incident(db, run, alert)
            incident = (
                db.query(sql_models.Incident)
                .filter(sql_models.Incident.wazuh_alert_id == alert_id)
                .first()
            )
            if incident:
                run.incident_id = incident.id
            changed = True
        elif detection_status == "unavailable":
            if run.wazuh_status != "unavailable" or run.ai_status != "unavailable":
                run.wazuh_status = "unavailable"
                run.ai_status = "unavailable"
                changed = True
        elif age > PENDING_ALERT_REFRESH_WINDOW:
            if run.wazuh_status != "not_detected":
                run.wazuh_status = "not_detected"
                run.ai_status = "not_analyzed"
                changed = True
        elif run.wazuh_status != "pending" or run.ai_status != "pending":
            run.wazuh_status = "pending"
            run.ai_status = "pending"
            changed = True

    if changed:
        db.commit()
        for run in runs:
            db.refresh(run)
    return [models.SimulationRunResponse.model_validate(run) for run in runs]


@router.post("/ssh-brute-force", response_model=models.SimulationRunResponse)
async def run_ssh_brute_force(db: Session = Depends(dependencies.get_db)):
    return await _execute_lab_scenario(
        db=db,
        scenario="ssh_brute_force",
        target=LAB_TARGET,
        simulator_path="/run",
        max_attempts=SSH_SIMULATOR_ATTEMPTS,
    )


@router.post("/port-scan", response_model=models.SimulationRunResponse)
async def run_port_scan(db: Session = Depends(dependencies.get_db)):
    return await _execute_lab_scenario(
        db=db,
        scenario="port_scan",
        target=PORT_SCAN_TARGET,
        simulator_path="/run/port-scan",
        max_attempts=PORT_SCAN_ATTEMPTS,
        expected_ports=PORT_SCAN_PORTS,
    )
