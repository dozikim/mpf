"""Repository layer.

Encapsulates all database access behind small, testable classes so the API
routers stay thin. Each repository takes a SQLAlchemy ``Session`` and exposes
query helpers with pagination / filtering / sorting baked in.
"""
