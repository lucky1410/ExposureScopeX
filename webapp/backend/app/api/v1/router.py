"""Aggregate all v1 API routers."""

from fastapi import APIRouter

from app.api.v1.ai import router as ai_router
from app.api.v1.asm import router as asm_router
from app.api.v1.integrations import router as integrations_router
from app.api.v1.assessments import router as assessments_router
from app.api.v1.assets import router as assets_router
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.findings import router as findings_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.operation_workspaces import router as operation_workspaces_router
from app.api.v1.reports import router as reports_router
from app.api.v1.resources import router as resources_router
from app.api.v1.search import router as search_router
from app.api.v1.settings import router as settings_router
from app.api.v1.tools import router as tools_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router
from app.api.v1.mcp_security import router as mcp_security_router
from app.api.v1.operations import router as operations_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(assessments_router)
api_router.include_router(assets_router)
api_router.include_router(vulnerabilities_router)
api_router.include_router(findings_router)
api_router.include_router(investigations_router)
api_router.include_router(resources_router)
api_router.include_router(search_router)
api_router.include_router(notifications_router)
api_router.include_router(operation_workspaces_router)
api_router.include_router(reports_router)
api_router.include_router(settings_router)
api_router.include_router(tools_router)
api_router.include_router(ai_router)
api_router.include_router(asm_router)
api_router.include_router(integrations_router)
api_router.include_router(mcp_security_router)
api_router.include_router(operations_router)
