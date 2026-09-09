"""Organization and User models."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)

    # Relationships
    users = relationship("User", back_populates="organization", lazy="selectin")
    assessments = relationship("Assessment", back_populates="organization", lazy="selectin")
    api_keys = relationship("ApiKey", back_populates="organization", lazy="selectin")
    investigations = relationship("Investigation", back_populates="organization", lazy="selectin")
    scan_authorizations = relationship(
        "ScanAuthorization", back_populates="organization", lazy="selectin"
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(20), nullable=False, default="analyst")  # admin/manager/analyst/viewer
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    assessments = relationship("Assessment", back_populates="created_by_user", lazy="selectin")
    notifications = relationship("Notification", back_populates="user", lazy="selectin")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="selectin")
    favorites = relationship("UserFavorite", back_populates="user", lazy="selectin")
