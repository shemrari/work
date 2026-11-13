from collections import Counter
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

MIN_TRAINING_ALERTS = 20
MODEL_NAME = "IsolationForest"
FEATURES_USED = [
    "rule_level",
    "agent_frequency",
    "source_frequency",
    "rule_frequency",
    "category_frequency",
    "location_frequency",
    "agent_hour_frequency",
    "hour_of_day_sin",
    "hour_of_day_cos",
    "timestamp_missing",
]


def _nested_value(alert: Dict[str, Any], parent: str, key: str) -> Any:
    value = alert.get(parent)
    if isinstance(value, dict):
        return value.get(key)
    return None


def _timestamp(alert: Dict[str, Any]) -> Optional[datetime]:
    value = alert.get("@timestamp") or alert.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _alert_keys(alert: Dict[str, Any]) -> Tuple[str, str, str, str, str, Optional[datetime], float]:
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}
    groups = rule.get("groups")
    if isinstance(groups, list) and groups:
        category = "|".join(str(group) for group in groups)
    else:
        category = str(rule.get("id") or decoder.get("name") or "unknown")

    timestamp = _timestamp(alert)
    source_ip = alert.get("srcip") or _nested_value(alert, "source", "ip")
    agent_key = str(agent.get("id") or agent.get("name") or "unknown")
    source_key = str(source_ip or agent.get("name") or agent.get("id") or "unknown")
    rule_key = str(rule.get("id") or "unknown")
    location_key = str(alert.get("location") or "unknown")

    try:
        rule_level = float(rule.get("level") or 0)
    except (TypeError, ValueError):
        rule_level = 0.0

    return agent_key, source_key, rule_key, category, location_key, timestamp, rule_level


def _features(alerts: List[Dict[str, Any]]) -> np.ndarray:
    keys = [_alert_keys(alert) for alert in alerts]
    total = len(alerts)

    agent_counts = Counter(item[0] for item in keys)
    source_counts = Counter(item[1] for item in keys)
    rule_counts = Counter(item[2] for item in keys)
    category_counts = Counter(item[3] for item in keys)
    location_counts = Counter(item[4] for item in keys)
    agent_hour_counts = Counter(
        (item[0], item[5].replace(minute=0, second=0, microsecond=0))
        for item in keys
        if item[5] is not None
    )

    feature_rows = []
    for agent, source, rule, category, location, timestamp, rule_level in keys:
        hour = timestamp.hour if timestamp is not None else 0
        time_angle = 2 * math.pi * hour / 24
        agent_hour_frequency = (
            math.log1p(agent_hour_counts[(agent, timestamp.replace(minute=0, second=0, microsecond=0))])
            if timestamp is not None
            else 0.0
        )
        feature_rows.append(
            [
                rule_level,
                agent_counts[agent] / total,
                source_counts[source] / total,
                rule_counts[rule] / total,
                category_counts[category] / total,
                location_counts[location] / total,
                agent_hour_frequency,
                math.sin(time_angle),
                math.cos(time_angle),
                0.0 if timestamp is not None else 1.0,
            ]
        )
    return np.asarray(feature_rows, dtype=np.float32)


def _normalized_scores(raw_scores: np.ndarray) -> List[float]:
    ordered = np.sort(raw_scores)
    count = len(ordered)
    if count <= 1:
        return [0.0] * count

    scores = []
    for raw_score in raw_scores:
        lower = np.searchsorted(ordered, raw_score, side="left")
        upper = np.searchsorted(ordered, raw_score, side="right")
        midpoint_rank = (lower + upper - 1) / 2
        scores.append(round(float(midpoint_rank / (count - 1) * 100), 2))
    return scores


def _risk_level(score: Optional[float]) -> str:
    if score is None:
        return "unrated"
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def analyze_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    count = len(alerts)
    base_results = [
        {
            "alert": alert,
            "anomaly_score": None,
            "is_anomaly": False,
            "risk_level": "unrated",
        }
        for alert in alerts
    ]

    if count < MIN_TRAINING_ALERTS:
        return {
            "model": MODEL_NAME,
            "analysis_status": "insufficient_data",
            "message": (
                f"Isolation Forest requires at least {MIN_TRAINING_ALERTS} alerts; "
                f"received {count}. No anomaly scores were generated."
            ),
            "minimum_training_alerts": MIN_TRAINING_ALERTS,
            "features_used": FEATURES_USED,
            "summary": {
                "alerts_analyzed": count,
                "anomalies_detected": 0,
                "average_score": None,
                "risk_level": "unrated",
            },
            "results": base_results,
            "anomalies": [],
        }

    feature_matrix = _features(alerts)
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    predictions = model.fit_predict(feature_matrix)
    raw_scores = -model.score_samples(feature_matrix)
    scores = _normalized_scores(raw_scores)

    results = []
    for alert, prediction, score in zip(alerts, predictions, scores):
        results.append(
            {
                "alert": alert,
                "anomaly_score": score,
                "is_anomaly": bool(prediction == -1),
                "risk_level": _risk_level(score),
            }
        )

    anomalies = [result for result in results if result["is_anomaly"]]
    average_score = round(float(np.mean(scores)), 2) if scores else 0.0
    anomaly_ratio = len(anomalies) / count
    if anomaly_ratio >= 0.2 or average_score >= 75:
        overall_risk = "high"
    elif anomalies or average_score >= 50:
        overall_risk = "elevated"
    else:
        overall_risk = "low"

    return {
        "model": MODEL_NAME,
        "analysis_status": "trained",
        "message": "Scores are relative to the analyzed alert batch, not calibrated probabilities.",
        "minimum_training_alerts": MIN_TRAINING_ALERTS,
        "features_used": FEATURES_USED,
        "summary": {
            "alerts_analyzed": count,
            "anomalies_detected": len(anomalies),
            "average_score": average_score,
            "risk_level": overall_risk,
        },
        "results": results,
        "anomalies": anomalies,
    }
