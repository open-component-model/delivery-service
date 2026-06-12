import datetime
import enum
import hashlib
import logging

import aiohttp.web
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import consts
import deliverydb.model as dm
import features
import util


logger: logging.Logger = logging.getLogger(name=__name__)

DIGEST_PARAM: str = 'digest'
CHUNK_SIZE: int = 4096


# Supported hash algorithms, value contains length of the hexdigest for validation
class Algorithm(enum.Enum):
    sha256 = {'length': 64}


async def _get_ref_from_store(db_session: sqlasync.session.AsyncSession) -> str:
    """
    Create a new large object in PostgreSQL and return its object ID.

    This function initializes an empty large object (LOB) in the PostgreSQL
    database that can subsequently be used to store blob data.

    Args:
        db_session: An async SQLAlchemy session for database operations.

    Returns:
        The object ID (OID) of the newly created large object as a string.

    Raises:
        Exception: If the large object creation fails in the database.
    """

    conn: sqlasync.AsyncConnection = await db_session.connection()

    # Create new large object
    result = await conn.exec_driver_sql(statement='SELECT lo_create(0)')
    oid = result.scalar()
    if not oid:
        logger.error(msg='Unable to create large object in db')
        raise

    return str(oid)


async def _stream_blob_to_store(
    ref: str,
    stream: aiohttp.StreamReader,
    hash_algorithm: str,
    db_session: sqlasync.session.AsyncSession,
) -> tuple[str, int]:
    """
    Stream a blob from an HTTP request into PostgreSQL large object storage.

    Reads data from the provided stream in chunks, writes it to a PostgreSQL
    large object, and computes the hash digest of the blob as it streams.

    Args:
        ref: The object ID (OID) of the large object to write to, as a string.
        stream: An aiohttp StreamReader containing the blob data.
        hash_algorithm: The name of the hash algorithm to use (e.g. 'sha256').
        db_session: An async SQLAlchemy session for database operations.

    Returns:
        A tuple of (digest, size) where:
        - digest: The computed digest in format 'algorithm:hexdigest'.
        - size: The total number of bytes written.
    """

    digest: hashlib._Hash = hashlib.new(name=hash_algorithm)
    size: int = 0

    conn: sqlasync.AsyncConnection = await db_session.connection()

    # Open LOB for writing
    result = await conn.exec_driver_sql(
        statement='SELECT lo_open(%(oid)s, %(mode)s)',
        parameters={'oid': ref, 'mode': int('0x60000', base=0)},  # 0x60000 = Read/Write mode
    )
    lo_fd = result.scalar()

    # Write in chunks
    while chunk := await stream.read(CHUNK_SIZE):
        await conn.exec_driver_sql(
            statement='SELECT lowrite(%(fd)s, %(data)s)',
            parameters={'fd': lo_fd, 'data': chunk},
        )
        size += len(chunk)
        digest.update(chunk)

    # Close LOB
    await conn.exec_driver_sql(
        statement='SELECT lo_close(%(fd)s)',
        parameters={'fd': lo_fd},
    )

    return f'{hash_algorithm}:{digest.hexdigest()}', size


async def _stream_blob_from_store(
    db_session: sqlasync.session.AsyncSession,
    ref: str,
    stream: aiohttp.web.StreamResponse,
) -> None:
    """
    Stream a blob from PostgreSQL large object storage to an HTTP response.

    Reads a blob from PostgreSQL large object storage in chunks and writes
    the data to an HTTP response stream.

    Args:
        db_session: An async SQLAlchemy session for database operations.
        ref: The object ID (OID) of the large object to read from, as a string.
        stream: An aiohttp StreamResponse to write the blob data to.

    Returns:
        None. Data is written directly to the response stream.
    """

    conn: sqlasync.AsyncConnection = await db_session.connection()

    # Open LOB for writing
    result = await conn.exec_driver_sql(
        statement='SELECT lo_open(%(oid)s, %(mode)s)',
        parameters={'oid': int(ref), 'mode': int('0x20000', base=0)},  # 0x20000 = Read mode
    )
    lo_fd = result.scalar()

    # Read LOB in chunks
    while True:
        result = await conn.exec_driver_sql(
            statement='SELECT loread(%(fd)s, %(len)s)',
            parameters={'fd': lo_fd, 'len': CHUNK_SIZE},
        )
        buffer = result.scalar()
        if not buffer:
            break
        await stream.write(data=buffer)

    # Close LOB
    await conn.exec_driver_sql(
        statement='SELECT lo_close(%(fd)s)',
        parameters={'fd': lo_fd},
    )


async def _delete_blob_from_store(
    ref: str,
    db_session: sqlasync.session.AsyncSession,
) -> None:
    """
    Delete a blob's large object from the PostgreSQL database.

    This function removes a large object (LOB) from the PostgreSQL blob storage
    system using the PostgreSQL lo_unlink function.

    Args:
        ref: The object ID (OID) of the large object to delete, as a string.
        db_session: An async SQLAlchemy session to execute the deletion query.
    """

    conn: sqlasync.AsyncConnection = await db_session.connection()
    lo_deleted = await conn.exec_driver_sql(
        statement=f'SELECT lo_unlink({ref})',
    )

    if not lo_deleted:
        logger.error('large object was not in the database')
        raise


def _create_response_header(
    blob_digest: str,
    creation_date: datetime.datetime,
    mime_type: str,
    size: int,
) -> dict[str, str]:

    return {
        'Digest': blob_digest,
        'Created': creation_date.strftime(format='%d/%m/%y %H:%M:%S %z'),
        'Content-Type': mime_type,
        'Content-Length': str(size),
    }


def _validate_and_sanitize_digest(blob_digest: str) -> str:
    """
    Validate and sanitize a blob digest string.

    Args:
        blob_digest: The digest string (format 'algorithm:hexdigest')

    Returns:
        The sanitized digest string in lowercase format

    Raises:
        aiohttp.web.HTTPBadRequest: If the digest is invalid
    """

    blob_digest = blob_digest.strip()

    if blob_digest.count(':') != 1:
        raise aiohttp.web.HTTPBadRequest(reason='Digest must be in format "algorithm:hexdigest"')

    digest_alg, hex_digest = blob_digest.split(':')

    if digest_alg not in Algorithm.__members__:
        raise aiohttp.web.HTTPBadRequest(
            reason=f'Hash algorithm "{digest_alg}" is not supported. Supported algorithms: \
              {", ".join(Algorithm.__members__.keys())}',
        )

    # Check if hexdigest contains only valid hex characters
    try:
        int(hex_digest, 16)
    except ValueError:
        raise aiohttp.web.HTTPBadRequest(
            reason='Hexdigest must contain only valid hexadecimal characters (0-9, a-f, A-F)',
        )

    # Validate hexdigest length for the algorithm
    expected_length: int = Algorithm[digest_alg].value['length']
    if expected_length and len(hex_digest) != expected_length:
        raise aiohttp.web.HTTPBadRequest(
            reason=f'Invalid hexdigest length for {digest_alg}. Expected {expected_length} \
              characters, got {len(hex_digest)}',
        )

    # Return lowercase sanitized version
    return f'{digest_alg.lower()}:{hex_digest.lower()}'


class Blob(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def post(self) -> aiohttp.web.Response:
        """
        ---
        description: Upload and store blobs
        tags:
        - Blob
        parameters:
        - in: header
          name: Digest
          required: true
          schema:
            type: string
          description: The digest of the blob in the format <hash alg>:<hexdigest>
        - in: header
          name: Content-Length
          required: true
          schema:
            type: integer
        - in: header
          name: Content-Type
          required: true
          schema:
            type: string
        requestBody:
          required: true
          description: The blob which should be stored in the blob store
          content:
            application/octet-stream:
              schema:
                type: string
                format: binary
        responses:
          "200":
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
            description: The blob is already available in the blob store
          "500":
            description: The blob could not be stored
        """

        headers = self.request.headers
        request_header = {
            'digest': util.param(
                params=headers,
                name='Digest',
                required=True,
            ),
            'size': util.param(
                params=headers,
                name='Content-Length',
                required=True,
            ),
            'mime_type': str(
                util.param(
                    params=headers,
                    name='Content-Type',
                    required=True,
                ),
            ),
        }

        sanitized_request_digest = _validate_and_sanitize_digest(request_header['digest'])

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        blob_metadata: dm.BlobStore | None = await db_session.get(
            entity=dm.BlobStore,
            ident=sanitized_request_digest,
        )

        if blob_metadata:
            raise aiohttp.web.HTTPUnprocessableEntity(
                text='A blob with the same digest is already in blob store',
            )

        hash_algorithm: str = sanitized_request_digest.split(':')[0]
        try:
            blob_ref: str = await _get_ref_from_store(db_session=db_session)

            blob_digest, size = await _stream_blob_to_store(
                ref=blob_ref,
                stream=self.request.content,
                hash_algorithm=hash_algorithm,
                db_session=db_session,
            )

        except:
            await db_session.rollback()
            raise aiohttp.web.HTTPServerError()

        if blob_digest != sanitized_request_digest:
            logger.info(msg='digest from request and blob did not match')
            await db_session.rollback()
            raise aiohttp.web.HTTPBadRequest()

        blob_metadata = dm.BlobStore(
            digest=blob_digest,
            creation_date=datetime.datetime.now(),
            size=size,
            mime_type=request_header['mime_type'],
            ref=blob_ref,
        )

        try:
            db_session.add(instance=blob_metadata)

        except:
            await db_session.rollback()
            raise aiohttp.web.HTTPServerError()

        response_header: dict[str, str] = _create_response_header(
            blob_digest=blob_metadata.digest,
            mime_type=blob_metadata.mime_type,
            size=0,
            creation_date=blob_metadata.creation_date,
        )

        await db_session.commit()
        return aiohttp.web.Response(
            headers=response_header,
            status=aiohttp.web.HTTPOk.status_code,
        )

    async def head(self) -> aiohttp.web.Response:
        """
        ---
        description: Request metadata of a blob by its digest
        tags:
        - Blob
        parameters:
        - in: query
          name: digest
          required: true
          schema:
            type: string
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
        """

        raw_request_digest: str = str(
            util.param(
                params=self.request.rel_url.query,
                name=DIGEST_PARAM,
                required=True,
            ),
        )

        sanitized_request_digest: str = _validate_and_sanitize_digest(blob_digest=raw_request_digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        try:
            db_statement = sa.select(
                dm.BlobStore.digest,
                dm.BlobStore.creation_date,
                dm.BlobStore.size,
                dm.BlobStore.mime_type,
            ).where(dm.BlobStore.digest == sanitized_request_digest)
            blob_metadata = (await db_session.execute(db_statement)).one_or_none()

        except:
            raise aiohttp.web.HTTPServerError()

        if not blob_metadata:
            raise aiohttp.web.HTTPNotFound(
                reason=f'The blob with the digest: {sanitized_request_digest} could not be found',
            )

        response_header: dict[str, str] = _create_response_header(
            blob_digest=blob_metadata.digest,
            mime_type=blob_metadata.mime_type,
            size=blob_metadata.size,
            creation_date=blob_metadata.creation_date,
        )

        return aiohttp.web.Response(
            headers=response_header,
            status=aiohttp.web.HTTPOk.status_code,
        )

    async def delete(self) -> aiohttp.web.Response:
        """
        ---
        description: Delete blob by its digest
        tags:
        - Blob
        parameters:
        - in: query
          name: digest
          required: true
          schema:
            type: string
          description: The digest of the blob in the format <hash alg>:<hexdigest>
        responses:
          "204":
            description: Blob successfully deleted from the blob store
          "400":
            description: Bad Request
          "404":
            description: Blob not found
        """

        raw_request_digest: str = str(
            util.param(
                params=self.request.rel_url.query,
                name=DIGEST_PARAM,
                required=True,
            ),
        )

        # Validate and sanitize the digest
        sanitized_request_digest: str = _validate_and_sanitize_digest(blob_digest=raw_request_digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        db_statement = sa.select(dm.BlobStore.ref).where(
            dm.BlobStore.digest == sanitized_request_digest,
        )
        blob_ref = (await db_session.execute(statement=db_statement)).one_or_none()

        if not blob_ref:
            logger.info(f'blob with digest {sanitized_request_digest} could not be found')
            raise aiohttp.web.HTTPNotFound(reason='The blob could not be found')

        try:
            await _delete_blob_from_store(ref=blob_ref.ref, db_session=db_session)

            db_statement = sa.delete(dm.BlobStore).where(
                dm.BlobStore.digest == sanitized_request_digest,
            )
            blob_deleted = await db_session.execute(db_statement)

            if blob_deleted.rowcount == 0:
                logger.error('the blob metadata was not found in the db')
                raise

        except:
            await db_session.rollback()
            raise aiohttp.web.HTTPServerError()

        await db_session.commit()
        return aiohttp.web.Response(status=aiohttp.web.HTTPNoContent.status_code)

    async def get(self) -> aiohttp.web.StreamResponse:
        """
        ---
        description: Request blobs based on parameters
        tags:
        - Blob
        parameters:
        - in: query
          name: digest
          required: true
          schema:
            type: string
        responses:
          "200":
            description: Blob successfully streamed to the client
            content:
              application/octet-stream:
                schema:
                  type: string
                  format: binary
          "400":
            description: The required parameters are not provided.
          "404":
            description: Blob not found
        """

        raw_request_digest: str = str(
            util.param(params=self.request.rel_url.query, name=DIGEST_PARAM, required=True),
        )

        sanitized_request_digest: str = _validate_and_sanitize_digest(blob_digest=raw_request_digest)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        db_statement = sa.select(dm.BlobStore).where(dm.BlobStore.digest == sanitized_request_digest)
        blob_metadata = (await db_session.execute(statement=db_statement)).one_or_none()

        if not blob_metadata:
            raise aiohttp.web.HTTPNotFound()

        response_header: dict[str, str] = _create_response_header(
            blob_digest=blob_metadata[0].digest,
            mime_type=blob_metadata[0].mime_type,
            size=blob_metadata[0].size,
            creation_date=blob_metadata[0].creation_date,
        )

        stream_response = aiohttp.web.StreamResponse(headers=response_header)
        await stream_response.prepare(request=self.request)

        try:
            await _stream_blob_from_store(
                db_session=db_session,
                stream=stream_response,
                ref=blob_metadata[0].ref,
            )
            await stream_response.write_eof()

        except:
            raise aiohttp.web.HTTPServerError()

        return stream_response
