"""DNS record model for asset DNS data."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class DnsRecord(TimestampMixin, Base):
    __tablename__ = "dns_records"

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    record_type = Column(
        String(10), nullable=False
    )  # A/AAAA/MX/NS/TXT/SOA/CAA/CNAME
    value = Column(String(1000), nullable=False)
    priority = Column(Integer, nullable=True)
    ttl = Column(Integer, nullable=True)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    is_demo = Column(Boolean, default=False, nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="dns_records")
