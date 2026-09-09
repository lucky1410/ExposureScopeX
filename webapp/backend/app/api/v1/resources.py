"""Resource library endpoints: list, categories, favorite toggle, favorites list."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.resource import Resource, UserFavorite
from app.models.user import User
from app.schemas.resource import ResourceList, ResourceResponse

router = APIRouter(prefix="/resources", tags=["Resources"])


@router.get("", response_model=ResourceList)
async def list_resources(
    category: str | None = None,
    search: str | None = None,
    is_featured: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List security resources with optional filtering."""
    base = select(Resource)

    if category:
        base = base.where(Resource.category == category)
    if is_featured is not None:
        base = base.where(Resource.is_featured == is_featured)
    if search:
        base = base.where(
            Resource.name.ilike(f"%{search}%")
            | Resource.description.ilike(f"%{search}%")
        )

    count_q = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    offset = (page - 1) * page_size
    result = await db.execute(
        base.order_by(Resource.display_order, Resource.name).offset(offset).limit(page_size)
    )
    resources = result.scalars().all()

    # Get user's favorites
    fav_result = await db.execute(
        select(UserFavorite.resource_id).where(UserFavorite.user_id == current_user.id)
    )
    fav_ids = {row[0] for row in fav_result.fetchall()}

    # Get distinct categories
    cat_result = await db.execute(select(distinct(Resource.category)).order_by(Resource.category))
    categories = [row[0] for row in cat_result.fetchall()]

    items = []
    for r in resources:
        items.append(
            ResourceResponse(
                id=r.id,
                category=r.category,
                subcategory=r.subcategory,
                name=r.name,
                description=r.description,
                url=r.url,
                icon=r.icon,
                tags=r.tags,
                is_featured=r.is_featured,
                display_order=r.display_order,
                is_favorited=r.id in fav_ids,
                created_at=r.created_at,
            )
        )

    return ResourceList(items=items, total=total, categories=categories)


@router.get("/categories", response_model=list[str])
async def list_categories(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all resource categories."""
    result = await db.execute(
        select(distinct(Resource.category)).order_by(Resource.category)
    )
    return [row[0] for row in result.fetchall()]


@router.post("/{resource_id}/favorite", status_code=status.HTTP_200_OK)
async def toggle_favorite(
    resource_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle favorite status of a resource for the current user."""
    # Verify resource exists
    rq = await db.execute(select(Resource).where(Resource.id == resource_id))
    if not rq.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    # Check existing favorite
    existing = await db.execute(
        select(UserFavorite).where(
            and_(
                UserFavorite.user_id == current_user.id,
                UserFavorite.resource_id == resource_id,
            )
        )
    )
    fav = existing.scalar_one_or_none()

    if fav:
        await db.delete(fav)
        await db.flush()
        return {"is_favorited": False}
    else:
        new_fav = UserFavorite(user_id=current_user.id, resource_id=resource_id)
        db.add(new_fav)
        await db.flush()
        return {"is_favorited": True}


@router.get("/favorites", response_model=list[ResourceResponse])
async def list_favorites(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's favorite resources."""
    result = await db.execute(
        select(Resource)
        .join(UserFavorite)
        .where(UserFavorite.user_id == current_user.id)
        .order_by(Resource.name)
    )
    resources = result.scalars().all()
    return [
        ResourceResponse(
            id=r.id,
            category=r.category,
            subcategory=r.subcategory,
            name=r.name,
            description=r.description,
            url=r.url,
            icon=r.icon,
            tags=r.tags,
            is_featured=r.is_featured,
            display_order=r.display_order,
            is_favorited=True,
            created_at=r.created_at,
        )
        for r in resources
    ]
