from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel

from backend.app.database.repository import repo
from backend.app.core.models import (
    OSINTIndicator,
    OSINTObservation,
    SecretExposureFinding,
    RecursivePivotJob,
    OSINTGraphNode,
    OSINTGraphEdge
)
from backend.app.analyzers.universal.osint_collector import osint_collector
from backend.app.analyzers.universal.secret_correlation import secret_engine
from backend.app.analyzers.universal.recursive_pivot_engine import recursive_pivot_engine
from backend.app.analyzers.universal.osint_graph_builder import osint_graph_builder
from backend.app.integrations.osint.osint_service import osint_service
from backend.app.core.user_auth import get_current_user

router = APIRouter(prefix="/api/osint", tags=["OSINT & Recursive Pivot"])

class EnrichRequest(BaseModel):
    indicator_ids: Optional[List[str]] = None
    force_refresh: bool = False

class PivotRequest(BaseModel):
    max_depth: int = 3
    budget_limit: int = 50
    seed_indicator_ids: Optional[List[str]] = None

@router.get("/investigations/{inv_id}/indicators", response_model=List[OSINTIndicator])
def get_indicators(
    inv_id: str,
    auto_collect: bool = True,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieve all direct and pivot-derived indicators for an investigation."""
    indicators = repo.list_osint_indicators(inv_id)
    if not indicators and auto_collect:
        detail = repo.get_universal_investigation_detail(inv_id)
        if detail:
            indicators = osint_collector.collect_from_investigation(detail)
            secret_engine.analyze_investigation_secrets(detail)
    return indicators

@router.post("/investigations/{inv_id}/collect")
def collect_indicators(
    inv_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Force re-scan and extract all evidence indicators and secret findings."""
    detail = repo.get_universal_investigation_detail(inv_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found")

    indicators = osint_collector.collect_from_investigation(detail)
    secrets = secret_engine.analyze_investigation_secrets(detail)
    return {
        "investigation_id": inv_id,
        "total_indicators_collected": len(indicators),
        "total_secrets_found": len(secrets),
        "indicators": indicators,
        "secrets": secrets
    }

@router.get("/investigations/{inv_id}/observations", response_model=List[OSINTObservation])
def get_observations(
    inv_id: str,
    indicator_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieve historical and live OSINT observations."""
    return repo.list_osint_observations(inv_id, indicator_id)

@router.post("/investigations/{inv_id}/enrich", response_model=List[OSINTObservation])
def enrich_indicators(
    inv_id: str,
    req: EnrichRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Enrich indicators with passive threat intelligence and network OSINT."""
    all_indicators = repo.list_osint_indicators(inv_id)
    if not all_indicators:
        detail = repo.get_universal_investigation_detail(inv_id)
        if detail:
            all_indicators = osint_collector.collect_from_investigation(detail)

    target_indicators = all_indicators
    if req.indicator_ids:
        target_indicators = [ind for ind in all_indicators if ind.id in req.indicator_ids]

    new_observations: List[OSINTObservation] = []
    for ind in target_indicators:
        obs_list = osint_service.enrich_indicator(ind, force_refresh=req.force_refresh)
        new_observations.extend(obs_list)

    return new_observations

@router.post("/investigations/{inv_id}/pivot", response_model=RecursivePivotJob)
def run_pivot(
    inv_id: str,
    req: PivotRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Execute bounded recursive infrastructure pivoting across DNS, CT, and RDAP."""
    job = recursive_pivot_engine.run_recursive_pivot(
        investigation_id=inv_id,
        max_depth=req.max_depth,
        budget_limit_queries=req.budget_limit,
        seed_indicator_ids=req.seed_indicator_ids
    )
    return job

@router.get("/investigations/{inv_id}/graph")
def get_osint_graph(
    inv_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Retrieve graph nodes and 16 relation edges for interactive visualization."""
    detail = repo.get_universal_investigation_detail(inv_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found")

    nodes, edges = osint_graph_builder.build_graph(detail)
    return {
        "investigation_id": inv_id,
        "nodes": [n.model_dump() for n in nodes],
        "edges": [e.model_dump() for e in edges],
        "total_nodes": len(nodes),
        "total_edges": len(edges)
    }

@router.get("/investigations/{inv_id}/secrets", response_model=List[SecretExposureFinding])
def get_secrets(
    inv_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieve isolated secret exposure findings with safety attestations."""
    return repo.list_secret_exposure_findings(inv_id)
