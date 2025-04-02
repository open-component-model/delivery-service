import sqlalchemy.dialects.postgresql as sap
import sqlalchemy.ext.asyncio as sqlasync

import deliverydb.model as dm


def do_raise(self):
    raise RuntimeError('JSONB is not allowed, use JSON instead')


# prevent usage of postgresql exclusive `JSONB`
sap.JSONB.__init__ = do_raise

sessionmakers: dict[tuple[int, int, int], sqlasync.async_sessionmaker[sqlasync.session.AsyncSession]] = {} # noqa: E501


async def _sqlalchemy_sessionmaker(
    db_url: str,
    pool_size: int=5,
    max_overflow: int=10,
    pool_timeout: int=30,
) -> sqlasync.async_sessionmaker[sqlasync.session.AsyncSession]:
    # don't use regular caching here to prevent issues with coroutines as return type
    if sessionmaker := sessionmakers.get((pool_size, max_overflow, pool_timeout)):
        return sessionmaker

    engine = sqlasync.create_async_engine(
        db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
    )

    async with engine.begin() as conn:
        await conn.run_sync(dm.Base.metadata.create_all)

    sessionmaker = sqlasync.async_sessionmaker(bind=engine)
    sessionmakers[(pool_size, max_overflow, pool_timeout)] = sessionmaker

    return sessionmaker


async def sqlalchemy_session(
    db_url: str,
    pool_size: int=5,
    max_overflow: int=10,
    pool_timeout: int=30,
) -> sqlasync.session.AsyncSession:
    '''
    Caller must close database-session.

    Using session object managed by `middleware.db_session_middleware` middleware is the preferred
    way to obtain a database-session.
    '''
    sessionmaker = await _sqlalchemy_sessionmaker(
        db_url=db_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
    )

    return sessionmaker()
