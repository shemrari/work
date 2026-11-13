from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ...models import pydantic_models as models
from ...models import sql_models
from .. import dependencies

router = APIRouter(prefix="/assets", tags=["assets"])

@router.get("/", response_model=List[models.AssetResponse])
def read_assets(skip: int = 0, limit: int = 100, db: Session = Depends(dependencies.get_db)):
    assets = db.query(sql_models.Asset).offset(skip).limit(limit).all()
    return [models.AssetResponse.model_validate(asset) for asset in assets]

@router.get("/{asset_id}", response_model=models.AssetResponse)
def read_asset(asset_id: int, db: Session = Depends(dependencies.get_db)):
    asset = db.query(sql_models.Asset).filter(sql_models.Asset.id == asset_id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return models.AssetResponse.model_validate(asset)

@router.post("/", response_model=models.AssetResponse)
def create_asset(asset: models.AssetCreate, db: Session = Depends(dependencies.get_db)):
    db_asset = sql_models.Asset(**asset.dict())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return models.AssetResponse.model_validate(db_asset)
