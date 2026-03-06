import dataclasses
import datetime
import enum
import hashlib
import logging

import aiohttp.web
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.exc as db_error

import consts
import deliverydb.model as dm
import features
import util


logger: logging.Logger = logging.getLogger(name=__name__)

DIGEST_PARAM: str = 'digest'
CHUNK_SIZE: int = 524288


class Algorithm(enum.Enum):
    sha256 = 'sha256'


@dataclasses.dataclass
class BlobAttribute:
    digest: str # The digest is stored in the format <algorithm>:<hexdigest>
    ref: int
    creation_date: datetime.datetime = datetime.datetime.now(tz=datetime.timezone.utc)
    size: int = 0
    mime_type: str = ''


@dataclasses.dataclass
class Header:
    digest: str = ''
    mime_type: str = ''
    size: int = 0
    creation_date: datetime.datetime = datetime.datetime.now()

    def create_response_header(self):
        return {'Digest': self.digest,
                'Created': self.creation_date.strftime(format='%d/%m/%y %H:%M:%S %z'),
                'Content-Type': self.mime_type,
                'Content-Length': str(self.size)}


async def _stream_blob_to_db(db_session: sqlasync.session.AsyncSession,
                             stream: aiohttp.StreamReader,
                             hash_algorithm: str) -> BlobAttribute:

    try:
        conn: sqlasync.AsyncConnection = await db_session.connection()
        digest: hashlib._Hash = hashlib.new(name=hash_algorithm)
        size: int = 0

        # Create new large object
        result = await conn.exec_driver_sql(
                                                            statement="SELECT lo_create(0)")
        oid = result.scalar()
        if not oid:
            logger.error(msg='Unable to create large object in db')
            raise

        # Open LOB for writing
        result = await conn.exec_driver_sql(
            statement="SELECT lo_open(%(oid)s, %(mode)s)",
            parameters={"oid": oid, "mode": int('0x60000', base=0)}  # 0x60000 = Read/Write mode
        )
        lo_fd = result.scalar()

        # Write in chunks
        while True:
            chunk: bytes = await stream.read(CHUNK_SIZE)
            if not chunk:
                break
            await conn.exec_driver_sql(
                statement="SELECT lowrite(%(fd)s, %(data)s)",
                parameters={"fd": lo_fd, "data": chunk}
            )
            size += len(chunk)
            digest.update(chunk)

        # Close LOB
        await conn.exec_driver_sql(
            statement="SELECT lo_close(%(fd)s)",
            parameters={"fd": lo_fd}
        )

        return BlobAttribute(
            digest=f'{Algorithm.sha256.value}:{digest.hexdigest()}',
            ref=int(oid),
            size=size)

    except db_error.DBAPIError as err:
        await db_session.rollback()
        logger.error(f'error writing the large object in the database: {err}')
        raise


async def _stream_blob_from_db(db_session: sqlasync.session.AsyncSession,
                               stream: aiohttp.web.StreamResponse,
                               ref: str):
    try:
        conn: sqlasync.AsyncConnection = await db_session.connection()

        # Open LOB for writing
        result = await conn.exec_driver_sql(
            statement='SELECT lo_open(%(oid)s, %(mode)s)',
            parameters={'oid': int(ref), 'mode': int('0x20000', base=0)}  # 0x20000 = Read mode
        )
        lo_fd = result.scalar()

        # Read LOB in chunks
        while True:
            result = await conn.exec_driver_sql(
                                                statement='SELECT loread(%(fd)s, %(len)s)',
                                                parameters={'fd': lo_fd, 'len': CHUNK_SIZE})
            buffer = result.scalar()
            if not buffer:
                break
            await stream.write(data=buffer)

        # Close LOB
        await conn.exec_driver_sql(
            statement="SELECT lo_close(%(fd)s)",
            parameters={"fd": lo_fd}
        )

    except db_error.DBAPIError as err:
        logger.error(f'error reading the large object from the database: {err}')
        raise


async def _delete_blob(db_session: sqlasync.session.AsyncSession, blob_digest: str, ref: str):

    try:

        conn: sqlasync.AsyncConnection = await db_session.connection()
        lo_deleted = await conn.exec_driver_sql(
            statement=f'SELECT lo_unlink({ref})')

        if not lo_deleted:
            logger.error('large object was not in the database')
            raise

        db_statement = sa.delete(dm.BlobStore).where(dm.BlobStore.digest == blob_digest)
        blob_deleted = await db_session.execute(db_statement)

        if blob_deleted.rowcount == 0:
            logger.error('the blob metadata was not found in the db')
            raise

        await db_session.commit()

    except db_error.DBAPIError as err:
        await db_session.rollback()
        logger.error(f'a database error occurred during deletion of blob {err}')
        raise

    except:
        await db_session.rollback()
        raise


def _check_alg_and_digest(blob_digest: str):
    try:
        digest_alg, _ = blob_digest.split(':')
    except ValueError:
        raise aiohttp.web.HTTPBadRequest(
            reason='Query parameter has an incorrect format')

    if digest_alg not in Algorithm.__members__:
        raise aiohttp.web.HTTPBadRequest(
            reason=f'Hash algorithm {digest_alg} is not valid')


class Blob(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def post(self) -> aiohttp.web.Response:
        '''
        ---
        description: Upload and store blobs
        tags:
        - Blob
        parameters:
        - in: header
          name: digest
          required: true
          type: string
          description: The digest of the blob in the format <hash alg>:<hexdigest>
        requestBody:
          description: The blob which should be stored in the blob store
          content:
            */*
          required: true
        responses:
          "201":
            description: Blob was successful stored in the blob store
            headers:
            Digest:
                description: The digest of the blob in the format <hash alg>:<hexdigest>
                schema:
                    type: string
            Created:
                description: The date, the blob was stored into the blob store
                schema:
                    type: string
            Content-Type:
                description: The mime-type of the blob
                schema:
                    type: string
          "400":
            description: The required parameters are not provided
          "422":
            description:  The blob is already available in the blob store
          "500":
            description: The blob could not be stored
        '''

        request_header = Header(
                digest=str(util.param(params=request_header, name='Digest', required=True)),
                size=int(util.param(params=request_header, name='Content-Length', required=True)),
                mime_type=str(util.param(params=request_header, name='Content-Type', required=True))
                )

        _check_alg_and_digest(request_header.digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        blob_metadata: dm.BlobStore | None = await db_session.get(entity=dm.BlobStore,
                                                                  ident=request_header.digest)

        if blob_metadata:
            raise aiohttp.web.HTTPUnprocessableEntity(
                reason='Blob already in blob store',
                text=f'A blob with the digest {request_header.digest} is already available in the blob store')

        try:
            blob_attributes: BlobAttribute = await _stream_blob_to_db(
                                        db_session=db_session,
                                        stream=self.request.content,
                                        hash_algorithm=request_header.digest.split(':')[0])

        except:
            await db_session.rollback()
            raise aiohttp.web.HTTPServerError()

        if blob_attributes.digest != request_header.digest.lower():
            await db_session.rollback()
            raise aiohttp.web.HTTPBadRequest()

        blob_attributes.mime_type = request_header.mime_type
        blob_attributes.creation_date = datetime.datetime.now(tz=datetime.timezone.utc)

        try:
            db_session.add(instance=dm.BlobStore(
                            digest=blob_attributes.digest,
                            creation_date=blob_attributes.creation_date,
                            size=blob_attributes.size,
                            mime_type=blob_attributes.mime_type,
                            ref=blob_attributes.ref
                        ))

            await db_session.commit()

        except db_error.DBAPIError as err:
            await db_session.rollback()
            logger.error(f'error writing the blob metadata in the database: {err}')
            raise aiohttp.web.HTTPServerError()

        except:
            await db_session.rollback()
            raise aiohttp.web.HTTPServerError()

        response_header: Header = Header(digest=blob_attributes.digest,
                                            mime_type=blob_attributes.mime_type,
                                            creation_date=blob_attributes.creation_date)

        return aiohttp.web.Response(headers=response_header.create_response_header(),
                            status=aiohttp.web.HTTPOk.status_code)

    async def head(self) -> aiohttp.web.Response:
        '''
        ---
        description: Request metadata of a blob by its digest
        tags:
        - Blob
        parameters:
        - in: query
          name: digest
          type: string
          required: true
          description: The digest of the blob in the format <hash alg>:<hexdigest>
        responses:
          "200":
            description: Blob was found in the blob store
            headers:
            Digest:
                description: The digest of the blob in the format <hash alg>:<hexdigest>
                schema:
                    type: string
            Created:
                description: The date, the blob was stored into the blob store
                schema:
                    type: string
            Content-Type:
                description: The mime-type of the blob
                schema:
                    type: string
            Content-Length:
                description: The size of the blob
                schema:
                    type: integer
            "400":
            description: The required parameters are not provided.
            "404":
            description: Blob not found
        '''

        blob_digest: str = str(util.param(
            params=self.request.rel_url.query, name=DIGEST_PARAM, required=True))

        _check_alg_and_digest(blob_digest=blob_digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        try:

            db_statement = sa.select(dm.BlobStore.digest, dm.BlobStore.creation_date,
                                     dm.BlobStore.size, dm.BlobStore.mime_type).where(
                                         dm.BlobStore.digest == blob_digest)
            blob_metadata = (await db_session.execute(db_statement)).one_or_none()

        except db_error.DBAPIError as err:
            logger.error(f'select failed: {err}')
            raise aiohttp.web.HTTPServerError()

        if not blob_metadata:
            raise aiohttp.web.HTTPNotFound(
                reason=f'The blob with the digest: {blob_digest} could not be found')

        response_header: Header = Header(digest=blob_metadata.digest,
                                             mime_type=blob_metadata.mime_type,
                                             size=blob_metadata.size,
                                             creation_date=blob_metadata.creation_date)

        return aiohttp.web.Response(headers=response_header.create_response_header(),
                            status=aiohttp.web.HTTPOk.status_code)

    async def delete(self) -> aiohttp.web.Response:
        '''
        ---
        description: Delete blob by his digest
        tags:
        - Blob
        parameters:
        - in: query
          name: digest
          type: string
          required: true
          description: The digest of the blob in the format <hash alg>:<hexdigest>
        responses:
          "204":
            description: Blob successfully deleted from the blob store
          "400":
            description: Bad Request
          "404":
            description: Blob not found
        '''

        blob_digest: str = str(util.param(
            params=self.request.rel_url.query, name=DIGEST_PARAM, required=True))

        _check_alg_and_digest(blob_digest=blob_digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        db_statement = sa.select(dm.BlobStore.ref).where(
            dm.BlobStore.digest == blob_digest)
        blob_ref = (await db_session.execute(statement=db_statement)).one_or_none()

        if not blob_ref:
            logger.info(f'blob with {blob_digest=} could not be found')
            raise aiohttp.web.HTTPNotFound(
                reason='The blob could not be found')

        try:
            await _delete_blob(db_session=db_session, blob_digest=blob_digest, ref=blob_ref.ref)

        except:
            raise aiohttp.web.HTTPServerError()

        return aiohttp.web.Response(status=aiohttp.web.HTTPNoContent.status_code)

    async def get(self) -> aiohttp.web.StreamResponse:
        '''
        ---
        description: Request blobs based on parameters
        tags:
        - Blob
        parameters:
        - in: query
          name: digest
          type: string
          required: true
        responses:
          "200":
            description: Blob successfully streamed to the client
            content:
              type: blob
          "400":
            description: The required parameters are not provided.
          "404":
            description: Blob not found
        '''

        blob_digest: str = str(util.param(
            params=self.request.rel_url.query, name=DIGEST_PARAM, required=True))

        _check_alg_and_digest(blob_digest=blob_digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        db_statement = sa.select(dm.BlobStore).where(
                                            dm.BlobStore.digest == blob_digest)
        blob_metadata = (await db_session.execute(statement=db_statement)).one_or_none()

        if not blob_metadata:
            raise aiohttp.web.HTTPNotFound()

        response_header: Header = Header(digest=blob_metadata[0].digest,
                                        mime_type=blob_metadata[0].mime_type,
                                        size=blob_metadata[0].size,
                                        creation_date=blob_metadata[0].creation_date)

        stream_response = aiohttp.web.StreamResponse(
            headers=response_header.create_response_header()
        )
        await stream_response.prepare(self.request)

        try:
            await _stream_blob_from_db(db_session=db_session,
                                       stream=stream_response,
                                       ref=blob_metadata[0].ref)
            await stream_response.write_eof()

        except:
            raise aiohttp.web.HTTPServerError()

        return stream_response
