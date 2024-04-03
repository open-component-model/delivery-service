import falcon.asgi

import deliverydb
import deliverydb.model as dm


class DBSessionLifecycle:
    '''
    Used to centrally manage database-session lifecycle.

    Create session object stored in request-context after request routing, available for all routes.
    Close session object at response post-processing.
    Optionally test database session.

    Using database-session from request-context is the preferred way.
    Consumers must still commit / rollback transactions.
    '''

    def __init__(
        self,
        db_url: str,
        verify_db_session: bool = True,
    ):
        self.db_url = db_url

        def test_db_session():
            session = deliverydb.sqlalchemy_session(self.db_url)
            # execute query to validate monkey-patched attributes
            session.query(dm.ArtefactMetaData).first()

        if verify_db_session:
            test_db_session()

    def process_resource(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource,
        params,
    ):
        req.context.db_session = deliverydb.sqlalchemy_session(self.db_url)

    def process_response(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        resource,
        req_succeeded: bool,
    ):
        if not resource:
            # may be None if no route was found for the request
            return

        if not hasattr(req.context, 'db_session'):
            return

        req.context.db_session.close()
