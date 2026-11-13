from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    ip_address = Column(String)
    os = Column(String)
    zone = Column(String)  # IT, OT, DMZ
    status = Column(String)  # active, inactive
    risk_level = Column(Integer)  # 1-5
    last_activity = Column(DateTime(timezone=True), server_onupdate=func.now())

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String)
    destination = Column(String)
    alert_type = Column(String)
    severity = Column(String)  # low, medium, high, critical
    status = Column(String)  # new, investigated, resolved
    ia_score = Column(Integer, nullable=True)  # 0-100
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ux_incidents_wazuh_alert_id", "wazuh_alert_id", unique=True),)

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String(20), nullable=True)
    status = Column(String)  # open, investigating, resolved
    source = Column(String(255), nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=True)
    anomaly_score = Column(Float, nullable=True)
    wazuh_alert_id = Column(String(255), nullable=True)
    wazuh_alert = Column(JSON, nullable=True)
    assigned_to = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        UniqueConstraint("incident_id", "action_type", name="uq_response_action_incident_type"),
    )

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(30), nullable=False)
    description = Column(Text, nullable=False)
    executed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    result = Column(String(50), nullable=False)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id = Column(Integer, primary_key=True, index=True)
    scenario = Column(String(80), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(30), nullable=False)
    attempt_count = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(Text, nullable=False)
    ports_tested = Column(JSON, nullable=True)
    wazuh_status = Column(String(30), nullable=False, default="pending")
    wazuh_alert_id = Column(String(255), nullable=True)
    wazuh_alert = Column(JSON, nullable=True)
    wazuh_rule_id = Column(String(80), nullable=True)
    wazuh_rule_level = Column(Integer, nullable=True)
    ai_status = Column(String(30), nullable=True)
    ai_score = Column(Float, nullable=True)
    incident_id = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)


class AuthUser(Base):
    __tablename__ = "auth_users"
    __table_args__ = (UniqueConstraint("email", name="uq_auth_users_email"),)

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(320), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_password_reset_tokens_hash"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
