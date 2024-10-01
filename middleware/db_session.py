import aiohttp.typedefs
import aiohttp.web
import sqlalchemy

import deliverydb
import deliverydb.model as dm


async def db_session_middleware(
    db_url: str,
    verify_db_session: bool=True,
) -> aiohttp.typedefs.Middleware:
    '''
    Used to centrally manage database-session lifecycle.

    Create session object stored in request-context after request routing, available for all routes.
    Close session object at response post-processing.
    Optionally test database session.

    Using database-session from request-context is the preferred way.
    Consumers must still commit / rollback transactions.
    '''

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        request[consts.REQUEST_DB_SESSION] = await deliverydb.sqlalchemy_session(db_url)

        response = await handler(request)

        if db_session := request.get(consts.REQUEST_DB_SESSION):
            await db_session.close()

        return response

    async def test_db_session():
        session = await deliverydb.sqlalchemy_session(db_url)
        # execute query to validate monkey-patched attributes
        await session.execute(sqlalchemy.select(dm.ArtefactMetaData).limit(1))
        await session.close()

    if verify_db_session:
        await test_db_session()

    return middleware
