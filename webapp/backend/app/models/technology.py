"""Technology model for detected software/frameworks on assets."""

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class Technology(TimestampMixin, Base):
    __tablename__ = "technologies"

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(200), nullable=False)
    version = Column(String(100), nullable=True)
    category = Column(String(100), nullable=True)
    source = Column(String(100), nullable=True)
    confidence = Column(Integer, nullable=True)  # 0-100
    is_demo = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("asset_id", "name", "version", name="uq_tech_asset_name_version"),
    )

    # Relationships
    asset = relationship("Asset", back_populates="technologies")
