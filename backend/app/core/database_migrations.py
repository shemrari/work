from sqlalchemy import DateTime, Float, Integer, JSON, String, inspect, text
from sqlalchemy.engine import Engine


INCIDENT_AI_COLUMNS = {
    "severity": String(20),
    "source": String(255),
    "detected_at": DateTime(timezone=True),
    "anomaly_score": Float(),
    "wazuh_alert_id": String(255),
    "wazuh_alert": JSON(),
}


def migrate_incident_ai_columns(engine: Engine) -> None:
    inspector = inspect(engine)
    if "incidents" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("incidents")}
    with engine.begin() as connection:
        for column_name, column_type in INCIDENT_AI_COLUMNS.items():
            if column_name not in existing_columns:
                compiled_type = column_type.compile(dialect=engine.dialect)
                connection.execute(
                    text(f"ALTER TABLE incidents ADD COLUMN {column_name} {compiled_type}")
                )

        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_incidents_wazuh_alert_id "
                "ON incidents (wazuh_alert_id)"
            )
        )


SIMULATION_RUN_COLUMNS = {
    "ports_tested": JSON(),
    "wazuh_rule_id": String(80),
    "wazuh_rule_level": Integer(),
    "ai_status": String(30),
    "ai_score": Float(),
    "incident_id": Integer(),
}


def migrate_simulation_run_columns(engine: Engine) -> None:
    inspector = inspect(engine)
    if "simulation_runs" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("simulation_runs")}
    with engine.begin() as connection:
        for column_name, column_type in SIMULATION_RUN_COLUMNS.items():
            if column_name not in existing_columns:
                compiled_type = column_type.compile(dialect=engine.dialect)
                connection.execute(
                    text(f"ALTER TABLE simulation_runs ADD COLUMN {column_name} {compiled_type}")
                )
