import datetime
import unittest.mock

import aiohttp.web
import jwt
import pytest

import middleware.auth


ISSUER = 'delivery_service'
JWT_KEY = 'foobar'
JWT_ALGORITHM = 'HS256'


def gen_jwt_payload():
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return {
        'version': 'v1',
        'sub': 'service_user',
        'iss': ISSUER,
        'iat': int((now-datetime.timedelta(minutes=10)).timestamp()),
        'exp': int((now+datetime.timedelta(minutes=5)).timestamp()),
        'key_id': '1',
    }


def gen_jwt_token(
    payload: dict,
    key: str = JWT_KEY,
    algorithm: str = JWT_ALGORITHM,
):
    return jwt.encode(
        payload=payload,
        key=key,
        algorithm=algorithm,
    )


@pytest.fixture()
def signing_cfg(
    key: str = JWT_KEY,
    algorithm: str = JWT_ALGORITHM,
):
    signing_cfg_mock = unittest.mock.Mock()
    signing_cfg_mock.private_key = key
    signing_cfg_mock.algorithm = algorithm

    return signing_cfg_mock


def test_valid_token():
    payload = gen_jwt_payload()
    middleware.auth.validate_jwt_payload(decoded_jwt=payload)


def test_no_exp():
    payload = gen_jwt_payload()
    payload.pop('exp')
    middleware.auth.validate_jwt_payload(decoded_jwt=payload)


def test_wrong_exp_format():
    payload = gen_jwt_payload()
    # will return float
    payload['exp'] = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_no_iss():
    payload = gen_jwt_payload()
    payload.pop('iss')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_wrong_iss(signing_cfg):
    payload = gen_jwt_payload()
    payload['iss'] = 'foo_bar'

    token = gen_jwt_token(payload=payload)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.decode_jwt(
            token=token,
            issuer=ISSUER,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )


def test_no_iat():
    payload = gen_jwt_payload()
    payload.pop('iat')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_future_iat(signing_cfg):
    payload = gen_jwt_payload()
    payload['iat'] = int((
        datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(minutes=100)
    ).timestamp())

    token = gen_jwt_token(payload=payload)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.decode_jwt(
            token=token,
            issuer=ISSUER,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )


def test_no_sub():
    payload = gen_jwt_payload()
    payload.pop('sub')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_sub_not_found():
    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.get_user_permissions('foo_bar_test_user')


def test_wrong_version():
    payload = gen_jwt_payload()
    payload['version'] = 'versionNotSet5000'

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_no_version():
    payload = gen_jwt_payload()
    payload.pop('version')

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.validate_jwt_payload(payload)


def test_nbf_in_past():
    payload = gen_jwt_payload()
    payload['nbf'] = int((
        datetime.datetime.now(tz=datetime.timezone.utc)
        - datetime.timedelta(minutes=100)
    ).timestamp())

    middleware.auth.validate_jwt_payload(payload)


def test_nbf_in_future(signing_cfg):
    payload = gen_jwt_payload()
    payload['nbf'] = int((
        datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(minutes=100)
    ).timestamp())

    token = gen_jwt_token(payload=payload)

    with pytest.raises(aiohttp.web.HTTPUnauthorized):
        middleware.auth.decode_jwt(
            token=token,
            issuer=ISSUER,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )
