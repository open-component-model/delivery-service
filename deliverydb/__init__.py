import sqlalchemy.dialects.postgresql as sap
import sqlalchemy.ext.asyncio as sqlasync

import deliverydb.model as dm


def do_raise(self):
    raise RuntimeError('JSONB is not allowed, use JSON instead')


# prevent usage of postgresql exclusive `JSONB`
sap.JSONB.__init__ = do_raise

sessionmaker = None


async def _sqlalchemy_sessionmaker(
    db_url: str,
) -> sqlasync.async_sessionmaker[sqlasync.session.AsyncSession]:
    # use singleton instead of caching to prevent issues with coroutines as return type
    global sessionmaker
    if sessionmaker:
        return sessionmaker

    engine = sqlasync.create_async_engine(
        db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
    )

    async with engine.begin() as conn:
        await conn.run_sync(dm.Base.metadata.create_all)

    sessionmaker = sqlasync.async_sessionmaker(bind=engine)
    return sessionmaker


async def sqlalchemy_session(db_url: str) -> sqlasync.session.AsyncSession:
    '''
    Caller must close database-session.

    Using session object managed by `DBSessionLifecycle` middleware is the preferred way to obtain
    a database-session.
    '''
    sessionmaker = await _sqlalchemy_sessionmaker(db_url=db_url)

    return sessionmaker()
