"""Port model for discovered network ports on assets."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Port(TimestampMixin, Base):
    __tablename__ = "ports"

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id"),
        nullable=True,
    )
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, default="tcp")  # tcp/udp
    state = Column(String(20), nullable=False, default="open")  # open/closed/filtered
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(200), nullable=True)
    banner = Column(Text, nullable=True)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", "port_number", "protocol", name="uq_port_scan_asset_port_proto"),
    )

    # Relationships
    asset = relationship("Asset", back_populates="ports")
    scan = relationship("Scan", back_populates="ports")
