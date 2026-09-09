"""TLS certificate model for SSL/TLS data on assets."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class TlsCertificate(TimestampMixin, Base):
    __tablename__ = "tls_certificates"

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_cn = Column(String(500), nullable=True)
    issuer = Column(String(500), nullable=True)
    not_before = Column(DateTime(timezone=True), nullable=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    fingerprint_sha256 = Column(String(128), nullable=True)
    key_size = Column(Integer, nullable=True)
    signature_algo = Column(String(100), nullable=True)
    sans = Column(JSONB, nullable=True, default=list)
    protocols = Column(JSONB, nullable=True, default=list)
    weak_protocols = Column(JSONB, nullable=True, default=list)
    is_demo = Column(Boolean, default=False, nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="tls_certificates")
