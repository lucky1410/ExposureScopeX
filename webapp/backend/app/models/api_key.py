"""API key model for storing encrypted external service credentials."""

from sqlalchemy import Boolean, Column, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class ApiKey(TimestampMixin, Base):
    __tablename__ = "api_keys"

    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name = Column(String(200), nullable=False)  # Human-readable label
    key_name = Column(String(100), nullable=False)  # e.g. SHODAN_API_KEY
    encrypted_value = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    creator = relationship("User", lazy="selectin")
