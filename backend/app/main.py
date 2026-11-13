from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import List
from .models import sql_models, pydantic_models
from .api import dependencies
from .api import routes
from .core.database_migrations import migrate_incident_ai_columns, migrate_simulation_run_columns
from .services.auth_security import ensure_initial_admin, require_application_session as auth_session_middleware

app = FastAPI(title="Industrial Cybersecurity Platform API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def require_application_session(request: Request, call_next):
    return await auth_session_middleware(request, call_next)

# Include routers
app.include_router(routes.auth.router)
app.include_router(routes.alerts.router)
app.include_router(routes.incidents.router)
app.include_router(routes.assets.router)
app.include_router(routes.wazuh.router)
app.include_router(routes.ai.router)
app.include_router(routes.simulations.router)
app.include_router(routes.reports.router)
app.include_router(routes.simulations.router, prefix="/api")
app.include_router(routes.reports.router, prefix="/api")

app.add_api_route(
    "/api/incidents",
    routes.incidents.read_incidents,
    methods=["GET"],
    response_model=List[pydantic_models.IncidentResponse],
    tags=["incidents"],
    name="read_incidents_api_compat",
)
app.add_api_route(
    "/api/incidents/sync-ai",
    routes.incidents.sync_ai_incidents,
    methods=["POST"],
    tags=["incidents"],
    name="sync_ai_incidents_api_compat",
)
app.add_api_route(
    "/api/incidents/response-actions/summary",
    routes.incidents.response_action_summary,
    methods=["GET"],
    tags=["incidents"],
    name="response_action_summary_api_compat",
)
app.add_api_route(
    "/api/incidents/{incident_id}/respond",
    routes.incidents.respond_to_incident,
    methods=["POST"],
    response_model=pydantic_models.SimulatedResponseActionResult,
    tags=["incidents"],
    name="respond_to_incident_api_compat",
)
app.add_api_route(
    "/api/incidents/{incident_id}/timeline",
    routes.incidents.read_incident_timeline,
    methods=["GET"],
    response_model=pydantic_models.IncidentTimelineResponse,
    tags=["incidents"],
    name="read_incident_timeline_api_compat",
)

@app.on_event("startup")
def on_startup():
    # Create database tables
    sql_models.Base.metadata.create_all(bind=dependencies.engine)
    migrate_incident_ai_columns(dependencies.engine)
    migrate_simulation_run_columns(dependencies.engine)
    with dependencies.SessionLocal() as db:
        ensure_initial_admin(db)

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/health", response_model=pydantic_models.HealthResponse)
def health_check(db: Session = Depends(dependencies.get_db)):
    try:
        # Execute a simple query to check DB connection
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {e}"
    return {"status": "ok", "database": db_status}
