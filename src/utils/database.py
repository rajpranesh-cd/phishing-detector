"""Database connection and operations manager."""

import asyncio
import asyncpg
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
import logging

from .config import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
    
    async def initialize(self):
        """Initialize database connection pool."""
        try:
            self.pool = await asyncpg.create_pool(
                settings.database_url,
                min_size=5,
                max_size=20,
                command_timeout=60
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
    
    async def close(self):
        """Close database connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool."""
        if not self.pool:
            raise RuntimeError("Database pool not initialized")
        
        async with self.pool.acquire() as connection:
            yield connection
    
    async def execute_query(self, query: str, *args) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return results."""
        async with self.get_connection() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(row) for row in rows]
    
    async def execute_command(self, command: str, *args) -> str:
        """Execute an INSERT/UPDATE/DELETE command."""
        async with self.get_connection() as conn:
            return await conn.execute(command, *args)
    
    async def execute_transaction(self, commands: List[tuple]) -> None:
        """Execute multiple commands in a transaction."""
        async with self.get_connection() as conn:
            async with conn.transaction():
                for command, args in commands:
                    await conn.execute(command, *args)


# Global database manager instance
db_manager = DatabaseManager()
