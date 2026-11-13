from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ...models import pydantic_models as models
from ...models import sql_models
from .. import dependencies

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/", response_model=List[models.AlertResponse])
def read_alerts(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db)):
    alerts = db.query(sql_models.Alert).offset(skip).limit(limit).all()
    return [models.AlertResponse.model_validate(alert) for alert in alerts]

@router.get("/{alert_id}", response_model=models.AlertResponse)
def read_alert(alert_id: int, db: Session = Depends(dependencies.get_db)):
    alert = db.query(sql_models.Alert).filter(sql_models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return models.AlertResponse.model_validate(alert)

@router.post("/", response_model=models.AlertResponse)
def create_alert(alert: models.AlertCreate, db: Session = Depends(dependencies.get_db)):
    db_alert = sql_models.Alert(**alert.dict())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return models.AlertResponse.model_validate(db_alert)
