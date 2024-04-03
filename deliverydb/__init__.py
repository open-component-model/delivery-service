import functools

import sqlalchemy.dialects.postgresql as sap
import sqlalchemy.orm.session

import deliverydb.model as dm


def do_raise(self):
    raise RuntimeError('JSONB is not allowed, use JSON instead')


# prevent usage of postgresql exclusive `JSONB`
sap.JSONB.__init__ = do_raise


@functools.cache
def _sqlalchemy_session(db_url: str) -> sqlalchemy.orm.session.Session:
    import sqlalchemy as sa

    engine = sa.create_engine(
        db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
    )

    Base = dm.Base
    Base.metadata.create_all(engine)

    return sa.orm.sessionmaker(bind=engine)


def sqlalchemy_session(db_url: str) -> sqlalchemy.orm.session.Session:
    '''
    Caller must close database-session.

    Using session object managed by `DBSessionLifecycle` middleware is the preferred way to obtain
    a database-session.
    '''
    return _sqlalchemy_session(db_url=db_url)()
