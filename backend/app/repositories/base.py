"""Generic paginated repository base."""
from __future__ import annotations

from typing import Generic, Sequence, TypeVar

from sqlalchemy import Select, asc, desc, func, select
from sqlalchemy.orm import Session

from app.db.session import Base

M = TypeVar("M", bound=Base)


class BaseRepository(Generic[M]):
    """Common query/pagination helpers for a single model.

    Subclasses set ``model`` and may set ``search_fields`` (column names that
    a free-text ``search`` param matches with ILIKE) and ``default_sort``.
    """

    model: type[M]
    search_fields: tuple[str, ...] = ()
    default_sort: str = "id"

    def __init__(self, session: Session):
        self.session = session

    # -- building blocks ----------------------------------------------------
    def _base_query(self, analysis_id: str) -> Select:
        return select(self.model).where(self.model.analysis_id == analysis_id)

    def _apply_search(self, stmt: Select, search: str | None) -> Select:
        if not search or not self.search_fields:
            return stmt
        term = f"%{search.lower()}%"
        clauses = [func.lower(getattr(self.model, f)).like(term)
                   for f in self.search_fields if hasattr(self.model, f)]
        if clauses:
            from sqlalchemy import or_
            stmt = stmt.where(or_(*clauses))
        return stmt

    def _apply_sort(self, stmt: Select, sort: str | None, order: str) -> Select:
        column_name = sort or self.default_sort
        if not hasattr(self.model, column_name):
            column_name = self.default_sort
        col = getattr(self.model, column_name)
        return stmt.order_by(desc(col) if order == "desc" else asc(col))

    # -- public API ---------------------------------------------------------
    def count(self, stmt: Select) -> int:
        return self.session.scalar(
            select(func.count()).select_from(stmt.order_by(None).subquery())
        ) or 0

    def paginate(self, analysis_id: str, *, page: int, page_size: int,
                 search: str | None = None, sort: str | None = None,
                 order: str = "asc",
                 extra_filters: Sequence | None = None) -> tuple[list[M], int]:
        stmt = self._base_query(analysis_id)
        for f in extra_filters or ():
            stmt = stmt.where(f)
        stmt = self._apply_search(stmt, search)
        total = self.count(stmt)
        stmt = self._apply_sort(stmt, sort, order)
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.scalars(stmt).all())
        return items, total

    def all_for(self, analysis_id: str,
                extra_filters: Sequence | None = None) -> list[M]:
        stmt = self._base_query(analysis_id)
        for f in extra_filters or ():
            stmt = stmt.where(f)
        return list(self.session.scalars(stmt).all())
