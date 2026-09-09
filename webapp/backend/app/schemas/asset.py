"""Asset schemas."""

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AssetResponse(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID
    asset_type: str
    value: str
    parent_id: Optional[uuid.UUID] = None
    is_live: bool
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata_: Optional[dict[str, Any]] = None
    is_demo: bool
    created_at: datetime
    updated_at: datetime
    canonical_key: Optional[str] = None
    normalized_value: Optional[str] = None
    root_domain: Optional[str] = None
    owner: Optional[str] = None
    ownership_status: str = "unattributed"
    related_count: int = 0
    asm_related_count: int = 0

    model_config = {"from_attributes": True}


class AssetUpdate(BaseModel):
    owner: Optional[str] = Field(default=None, max_length=255)
    ownership_status: Optional[str] = Field(default=None, pattern="^(confirmed|inferred|disputed|unattributed)$")
    is_live: Optional[bool] = None


class PortResponse(BaseModel):
    id: uuid.UUID
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    model_config = {"from_attributes": True}


class DnsRecordResponse(BaseModel):
    id: uuid.UUID
    record_type: str
    value: str
    priority: Optional[int] = None
    ttl: Optional[int] = None

    model_config = {"from_attributes": True}


class TechnologyResponse(BaseModel):
    id: uuid.UUID
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[int] = None

    model_config = {"from_attributes": True}


class TlsCertificateResponse(BaseModel):
    id: uuid.UUID
    subject_cn: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    fingerprint_sha256: Optional[str] = None
    key_size: Optional[int] = None
    signature_algo: Optional[str] = None
    sans: Optional[list[str]] = None
    protocols: Optional[list[str]] = None
    weak_protocols: Optional[list[str]] = None

    model_config = {"from_attributes": True}


class HttpHeaderResponse(BaseModel):
    id: uuid.UUID
    url: Optional[str] = None
    headers: Optional[dict[str, Any]] = None
    missing_headers: Optional[list[str]] = None
    cors_policy: Optional[str] = None
    server_header: Optional[str] = None
    checked_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AssetDetail(AssetResponse):
    ports: list[PortResponse] = []
    dns_records: list[DnsRecordResponse] = []
    technologies: list[TechnologyResponse] = []
    tls_certificates: list[TlsCertificateResponse] = []
    http_headers: list[HttpHeaderResponse] = []


class AssetList(BaseModel):
    items: list[AssetResponse]
    total: int
    page: int
    page_size: int


class InventoryRelation(BaseModel):
    source_key: str
    target_key: str
    relation: str


class InventoryAsset(BaseModel):
    canonical_key: str
    normalized_value: str
    primary_type: str
    hostname: Optional[str] = None
    root_domain: Optional[str] = None
    related_keys: list[str] = []
    assessment_ids: list[str] = []
    asm_target_ids: list[str] = []
    assessment_asset_ids: list[str] = []
    source_types: list[str] = []
    values: list[str] = []
    statuses: dict[str, int] = {}
    metadata: dict[str, Any] = {}


class InventoryAssetList(BaseModel):
    items: list[InventoryAsset]
    relations: list[InventoryRelation]
    total: int
