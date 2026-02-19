import logging
import hashlib
from datetime import datetime, timezone
import magic
from typing import Any
import io

from aiohttp import web
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.exc as db_error

import consts
import features
import util
import deliverydb.model as dm


BLOB_DIGEST = 'Digest'
BLOB_DATE = 'Date'
BLOB_SIZE = 'Size'
BLOB_TYPE = 'Content-Type'

logger: logging.Logger = logging.getLogger(name=__name__)


async def _write_blob(db_session: sqlasync.session.AsyncSession, digest: str, blob: bytes) -> dict[str, Any]:

  try:

    size = blob.__sizeof__()
    creation_date = datetime.now(tz=timezone.utc)
    mime_type = magic.from_buffer(buffer=blob, mime=True)

    db_statement = sa.insert(dm.BlobStore).values(digest=digest, creation_date=creation_date, size=size, mime_type=mime_type, blob=blob)
    dataset: sa.engine.cursor.CursorResult = await db_session.execute(db_statement)

    await db_session.commit()
    logger.info(f'blob with digest {digest} was successfully stored in the database')
    return {BLOB_DIGEST: digest, BLOB_DATE: creation_date.strftime('%d/%m/%y %H:%M:%S'), BLOB_SIZE: size, BLOB_TYPE: mime_type}
  
  except db_error.DBAPIError as err:

    await db_session.rollback()
    logger.error(f'blob could not be stored in the database: {err}')


async def _delete_blob(db_session: sqlasync.session.AsyncSession, hexdigest: str) -> int | None:

  try:

    db_statement = sa.delete(dm.BlobStore).where(dm.BlobStore.digest == hexdigest)
    dataset: sa.engine.cursor.CursorResult = await db_session.execute(db_statement)

    await db_session.commit()
  
    return dataset.rowcount
  
  except db_error.DBAPIError as err:

    await db_session.rollback()
    logger.error(f'blob could not be deleted : {err}')


async def _get_blob_by_digest(db_session: sqlasync.session.AsyncSession, hexdigest:str, metadata_only: bool = False):

  try:
    if metadata_only:
      db_statement = sa.select(dm.BlobStore.digest, dm.BlobStore.creation_date, dm.BlobStore.size, dm.BlobStore.mime_type).where(dm.BlobStore.digest == hexdigest)
    
    else:
      db_statement = sa.select(dm.BlobStore).where(dm.BlobStore.digest == hexdigest)

    return (await db_session.execute(db_statement)).one_or_none()

  except db_error.DBAPIError as err:
    logger.error(f'select failed: {err}')


def _get_hash(algorithm: str, blob: bytes) -> str:
   
  hash = hashlib.new(algorithm)
  hash.update(blob)

  return f'{algorithm}:{hash.hexdigest()}'


def _create_response(dataset: sa.Row[Any]) -> dict[str, Any]:

  return {
    BLOB_DIGEST: dataset.digest,
    BLOB_DATE: dataset.creation_date.strftime('%d/%m/%y %H:%M:%S'),
    BLOB_SIZE: str(dataset.size),
    BLOB_TYPE: dataset.mime_type
  }


class Blob(web.View):
  required_features = (features.FeatureDeliveryDB,)

  async def post(self) -> web.Response:
    '''
    ---
    description: upload and store blobs
    tags:
    - blob
    parameters:
    - in: body
      required: true
      schema:
        type: blob
    responses:
      "201":
        description: Blob successfully uploaded
        content:
          application/json:
            schema:
              type: object
              properties:
                digest:
                  type: string
                created_at:
                  type: string
                size:
                  type: string
                mime-type:
                  type: string
      "400":
        description: Bad Request. The required parameters are not provided.
      "500":
        description: Internal Server Error. The blob could not be stored
    '''

    algorithm = 'sha256'
    db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

    try:

      blob_content: bytes = await self.request.read()
      blob_digest: str = _get_hash(algorithm=algorithm, blob=blob_content)
      logger.info(msg=f'blob digest: {blob_digest}')

      stored_blob: sa.Row[Any] | None = await _get_blob_by_digest(db_session=db_session, hexdigest=blob_digest)

      if stored_blob:

        logger.info(msg=f'blob already exists: {blob_digest}')
        server_response = _create_response(stored_blob[0])
        #server_response['status'] = 'The resource already exists'
        status_code = 200
      else:

        logger.info(msg='blob does not exist, must be stored')
        server_response: dict[str, Any] = await _write_blob(db_session=db_session, digest=blob_digest, blob=blob_content)
        #server_response['status'] = 'The blob was stored successful'
        status_code = 201

      logger.info(msg=server_response)
      return web.json_response(data=server_response, status=status_code)

    except:
      return web.HTTPServerError(reason='The POST request could not be processed')


  async def head(self) -> web.Response:
    '''
      ---
      description: Request metadata of a blob by his digest
      tags:
      - blob
      parameters:
      - in: query
        name: digest
        type: string
        required: true
      responses:
        "200":
          description: Blob successfully received
          content:
            type: application/json
              schema:
                type: object
                properties:
                  digest:
                    type: string
                  created_at:
                    type: string
                  size:
                    type: string
                  mime-type:
                    type: string
        "400":
          description: Bad Request. The required parameters are not provided.
        "404":
          description: Blob not found
    '''
      
    params = self.request.rel_url.query
    blob_digest: str = util.param(params=params, name=BLOB_DIGEST.lower(), required=True)

    if len(blob_digest.split(':')) != 2 or blob_digest.find(':') != 6: 
      raise web.HTTPBadRequest(reason=f'Parameter "{BLOB_DIGEST}" has an incorrect format', text=blob_digest)
    
    db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
    blob_metadata = await _get_blob_by_digest(db_session=db_session, hexdigest=blob_digest, metadata_only=True)

    if not blob_metadata:
      raise web.HTTPNotFound(reason=f'The blob with the digest: {blob_digest} could not be found')

    response_header: dict[str, Any] = _create_response(blob_metadata)
    status_code = 200

    return web.Response(headers=response_header, status=status_code)


  async def get(self) -> web.StreamResponse:
    '''
    ---
    description: Request blobs based on parameters
    tags:
    - blob
    parameters:
    - in: query
      name: digest
      type: string
      required: true
    responses:
      "200":
        description: Blob successfully received
        content:
          type: blob
      "400":
        description: Bad Request. The required parameters are not provided.
      "404":
        description: Blob not found
    '''

    params = self.request.rel_url.query
    blob_digest: str = util.param(params=params, name=BLOB_DIGEST.lower(), required=True)

    if len(blob_digest.split(':')) != 2 or blob_digest.find(':') != 6: 
      raise web.HTTPBadRequest(reason=f'Parameter "{BLOB_DIGEST}" has an incorrect format', text=blob_digest)
    
    db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
    blob_data = await _get_blob_by_digest(db_session=db_session, hexdigest=blob_digest)

    if not blob_data:
      raise web.HTTPNotFound(reason=f'The blob with the digest: {blob_digest} could not be found')

    response = web.StreamResponse(
        headers={
            BLOB_TYPE: blob_data[0].mime_type
        }
    )
    await response.prepare(self.request)

    byte_stream = io.BytesIO(initial_bytes=blob_data[0].blob)
    while True:
      chunk = byte_stream.read(4096)
      if not chunk:
        break
      await response.write(data=chunk)
    
    await response.write_eof()
    return response


  async def delete(self) -> web.Response:
    '''
      ---
      description: Delete blob by his digest
      tags:
      - blob
      parameters:
      - in: query
        name: digest
        type: string
        required: true
      responses:
        "200":
          description: Blob successfully deleted
        "400":
          description: Bad Request. The required parameters are not provided.
        "404":
          description: Blob not found
    '''
      
    params = self.request.rel_url.query
    blob_digest: str = util.param(params=params, name=BLOB_DIGEST.lower(), required=True)

    if len(blob_digest.split(':')) != 2 or blob_digest.find(':') != 6: 
      raise web.HTTPBadRequest(reason=f'Parameter "{BLOB_DIGEST}" has an incorrect format', text=blob_digest)
    
    db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
    row_count = await _delete_blob(db_session=db_session, hexdigest=blob_digest)

    if row_count == 0:
      raise web.HTTPNotFound(reason=f'The blob with the digest {blob_digest} could not be found')
    
    return web.Response(text='', status=200)