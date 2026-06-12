import datetime

import Crypto.PublicKey.RSA
import jwt
import pytest

import odg_client.jwt


ISSUER = 'test-issuer'
private_key = Crypto.PublicKey.RSA.generate(4096)
public_key = private_key.public_key()


@pytest.fixture
def json_web_key() -> odg_client.jwt.JSONWebKey:
    return odg_client.jwt.JSONWebKey.from_dict(
        data={
            'use': odg_client.jwt.Use.SIGNATURE,
            'kid': 'foo',
            'alg': odg_client.jwt.Algorithm.RS256,
            'n': odg_client.jwt.encodeBase64urlUInt(public_key.n),
            'e': odg_client.jwt.encodeBase64urlUInt(private_key.e),
        },
    )


@pytest.fixture
def token() -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    time_delta = datetime.timedelta(days=730)  # 2 years

    token = {
        'version': 'v1',
        'sub': 'test-user',
        'iss': ISSUER,
        'iat': int(now.timestamp()),
        'github_oAuth': {
            'host': 'github',
            'team_names': [],
            'email_address': 'test-user@email.com',
        },
        'exp': int((now + time_delta).timestamp()),
        'key_id': '0',
    }

    return jwt.encode(
        payload=token,
        key=private_key.export_key(format='PEM'),
        algorithm=odg_client.jwt.Algorithm.RS256,
    )


def test_jwt(json_web_key, token):
    # token was just created and thus is not expired yet
    assert not odg_client.jwt.is_jwt_token_expired(
        token=token,
    )

    # this is a correct token validation
    odg_client.jwt.decode_jwt(
        token=token,
        verify_signature=True,
        json_web_key=json_web_key,
        issuer=ISSUER,
    )

    # no key supplied but token validation requested
    with pytest.raises(ValueError):
        odg_client.jwt.decode_jwt(
            token=token,
            verify_signature=True,
            json_web_key=None,
            issuer=ISSUER,
        )

    # token validation but with wrong issuer
    with pytest.raises(jwt.exceptions.InvalidIssuerError):
        odg_client.jwt.decode_jwt(
            token=token,
            verify_signature=True,
            json_web_key=json_web_key,
            issuer='wrong-issuer',
        )
