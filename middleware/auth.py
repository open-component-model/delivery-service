import collections.abc
import dataclasses
import datetime
import enum
import functools
import logging
import urllib.parse

import aiohttp
import aiohttp.typedefs
import aiohttp.web
import Crypto.PublicKey.RSA
import dacite
import jsonschema
import jsonschema.exceptions
import jwt
import yaml

import ci.util
import config
import consts
import delivery.jwt
import model
import model.github

import paths


logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class GithubUser():
    username: str
    github_hostname: str
    type: str = 'github-user'


class GithubRoutes:
    def __init__(self, api_url: str):
        self.api_url = api_url

    def _url(self, *parts):
        return ci.util.urljoin(
            self.api_url,
            *parts,
        )

    def current_user(self):
        return self._url('user')

    def current_user_teams(self):
        return self._url('user', 'teams')

    def current_user_orgs(self):
        return self._url('user', 'orgs')


class GithubApi:
    def __init__(self, routes: GithubRoutes, oauth_token: str):
        self._routes = routes
        self._oauth_token = oauth_token
        self.session = aiohttp.ClientSession()

    async def _get(self, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        headers = kwargs['headers']
        headers['Authorization'] = f'token {self._oauth_token}'

        async with self.session.get(*args, **kwargs) as res:
            res.raise_for_status()

            return await res.json()

    async def current_user(self):
        return await self._get(self._routes.current_user())

    async def current_user_teams(self):
        return await self._get(self._routes.current_user_teams())

    async def current_user_orgs(self):
        return await self._get(self._routes.current_user_orgs())

    async def close_connection(self):
        await self.session.close()


class AuthType(enum.Enum):
    NONE = None
    BEARER = 'Bearer'


def noauth(cls):
    '''
    class decorator used to disable authentication for the receiving aiohttp request handler
    '''
    cls.auth = AuthType.NONE
    return cls


@functools.cache
def token_payload_schema():
    return yaml.safe_load(open(paths.token_jsonschema_path, 'rb'))


def _check_if_oauth_feature_available() -> 'features.FeatureAuthentication':
    # Use this function instead of feature checking middleware to prevent
    # circular module imports between middleware.auth.py and features.py
    import features
    feature_authentication = features.get_feature(features.FeatureAuthentication)

    if feature_authentication.state == features.FeatureStates.AVAILABLE:
        return feature_authentication

    import util
    raise aiohttp.web.HTTPBadRequest(
        reason='Feature is inactive',
        text=util.dict_to_json_factory({
            'error_id': 'feature-inactive',
            'missing_features': [feature_authentication.name],
        }),
        content_type='application/json',
    )


@noauth
class OAuthCfgs(aiohttp.web.View):
    async def get(self):
        '''
        ---
        tags:
        - Authentication
        produces:
        - application/json
        responses:
          "200":
            description: Successful operation.
            schema:
              $ref: '#/definitions/AuthConfig'
        '''
        def oauth_cfg_to_dict(oauth_cfg: config.OAuthCfg):
            cfg_factory = self.request.app[consts.APP_CFG_FACTORY]
            github_cfg = cfg_factory.github(oauth_cfg.github_cfg)
            github_host = urllib.parse.urlparse(github_cfg.api_url()).hostname.lower()

            redirect_uri = ci.util.urljoin(
                self.request.app[consts.APP_BASE_URL],
                'auth',
            ) + '?' + urllib.parse.urlencode({
                'client_id': oauth_cfg.client_id,
            })

            oauth_url = oauth_cfg.oauth_url.rstrip('?') + '?' + urllib.parse.urlencode({
                'client_id': oauth_cfg.client_id,
                'scope': oauth_cfg.scope,
                'redirect_uri': redirect_uri,
            })

            return {
                'name': oauth_cfg.name,
                'github_name': oauth_cfg.github_cfg,
                'github_host': github_host,
                'api_url': github_cfg.api_url(),
                'oauth_url': oauth_cfg.oauth_url,
                'client_id': oauth_cfg.client_id,
                'scope': oauth_cfg.scope,
                'redirect_uri': redirect_uri,
                'oauth_url_with_redirect': oauth_url,
            }

        feature_authentication = _check_if_oauth_feature_available()

        return aiohttp.web.json_response(
            data=[
                oauth_cfg_to_dict(oauth_cfg)
                for oauth_cfg in feature_authentication.oauth_cfgs
            ],
        )


@noauth
class OAuthLogin(aiohttp.web.View):
    async def get(self):
        '''
        ---
        tags:
        - Authentication
        produces:
        - application/json
        parameters:
        - in: query
          name: code
          type: string
          required: false
        - in: query
          name: client_id
          type: string
          required: false
        - in: query
          name: access_token
          type: string
          required: false
        - in: query
          name: api_url
          type: string
          required: false
        responses:
          "200":
            description: Successfully logged in.
            schema:
              $ref: '#/definitions/AuthToken'
          "401":
            description: The provided auth information is not valid.
        '''
        feature_authentication = _check_if_oauth_feature_available()

        import util
        params = self.request.rel_url.query
        code = util.param(params, 'code')
        client_id = util.param(params, 'client_id')
        access_token = util.param(params, 'access_token')
        api_url = util.param(params, 'api_url')

        if not ((access_token and api_url) or (client_id and code)):
            raise aiohttp.web.HTTPUnauthorized(
                headers={
                    'WWW-Authenticate': (
                        'Add either the url query params "code" and "client_id" '
                        'or a valid "access_token" with a github "api_url"'
                    ),
                },
            )

        cfg_factory = self.request.app[consts.APP_CFG_FACTORY]

        if not access_token:
            for oauth_cfg in feature_authentication.oauth_cfgs:
                if oauth_cfg.client_id == client_id:
                    break
            else:
                client_ids = [
                    oauth_cfg.client_id for oauth_cfg in feature_authentication.oauth_cfgs
                ]
                raise aiohttp.web.HTTPUnauthorized(
                    headers={
                        'WWW-Authenticate': (
                            f'no such client: {client_id}; available clients: {client_ids}'
                        ),
                    },
                )

            # exchange code for bearer token
            github_oauth_url = oauth_cfg.token_url + '?' + \
                urllib.parse.urlencode({
                    'client_id': oauth_cfg.client_id,
                    'client_secret': oauth_cfg.client_secret,
                    'code': code,
                })

            async with aiohttp.ClientSession() as session:
                async with session.post(url=github_oauth_url) as res:
                    res.raise_for_status()

                    parsed = urllib.parse.parse_qs(await res.text())

            access_token = parsed.get('access_token')

            if not access_token:
                raise aiohttp.web.HTTPInternalServerError(
                    text=f'GitHub api did not return an access token. {parsed}',
                )

            access_token = access_token[0]

            github_cfg: model.github.GithubConfig = cfg_factory.github(oauth_cfg.github_cfg)
            api_url = github_cfg.api_url()
        else:
            for oauth_cfg in feature_authentication.oauth_cfgs:
                github_cfg: model.github.GithubConfig = cfg_factory.github(oauth_cfg.github_cfg)
                if github_cfg.api_url() == api_url:
                    break

            else:
                raise aiohttp.web.HTTPUnauthorized

        gh_routes = GithubRoutes(api_url=api_url)
        gh_api = GithubApi(
            routes=gh_routes,
            oauth_token=access_token,
        )
        github_host = urllib.parse.urlparse(api_url).hostname.lower()

        try:
            github_orgs = [
                org['login']
                for org in await gh_api.current_user_orgs()
            ]

            github_teams = [
                '/'.join((team['organization']['login'], team['name']))
                for team in await gh_api.current_user_teams()
            ]

            user = await gh_api.current_user()
            username = user['login']

        except Exception as e:
            logger.warning(f'failed to retrieve user info for {api_url=}: {e}')
            raise aiohttp.web.HTTPUnauthorized
        finally:
            await gh_api.close_connection()

        delivery_cfg = cfg_factory.delivery(self.request.app[consts.APP_DELIVERY_CFG])
        delivery_cfg = dacite.from_dict(
            data=delivery_cfg.raw,
            data_class=config.DeliveryCfg,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

        def find_subject(
            subjects: list[config.Subject],
            username: str,
            github_orgs: list[str],
            github_teams: list[str],
        ) -> config.Subject | None:
            for subject in subjects:
                if subject.type is config.SubjectType.GITHUB_USER:
                    if subject.name == username:
                        return subject

                elif subject.type is config.SubjectType.GITHUB_ORG:
                    if subject.name in github_orgs:
                        return subject

                elif subject.type is config.SubjectType.GITHUB_TEAM:
                    if subject.name in github_teams:
                        return subject

        roles = set()

        for role_binding in oauth_cfg.role_bindings:
            if find_subject(
                subjects=role_binding.subjects,
                username=username,
                github_orgs=github_orgs,
                github_teams=github_teams,
            ):
                roles.update(role_binding.roles)

        if config.Role.ADMIN not in roles:
            raise aiohttp.web.HTTPUnauthorized(
                text='user is not authorised to access this service',
            )

        if not delivery_cfg.signing_cfgs:
            raise aiohttp.web.HTTPInternalServerError(
                text='could not retrieve matching signing cfgs',
            )

        signing_cfg = sorted(
            delivery_cfg.signing_cfgs,
            key=lambda cfg: cfg.priority,
            reverse=True,
        )[0]

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        time_delta = datetime.timedelta(days=730) # 2 years

        token = {
            'version': 'v1',
            'sub': username,
            'iss': self.request.app[consts.APP_BASE_URL],
            'iat': int(now.timestamp()),
            'github_oAuth': {
                'host': github_host,
                'team_names': github_teams,
                'org_names': github_orgs,
                'email_address': user.get('email'),
            },
            'exp': int((now + time_delta).timestamp()),
            'key_id': signing_cfg.id,
        }

        response = aiohttp.web.json_response(
            data=token,
        )

        response.set_cookie(
            name=delivery.jwt.JWT_KEY,
            value=jwt.encode(
                token,
                signing_cfg.private_key,
                algorithm=signing_cfg.algorithm,
            ),
            httponly=True,
            samesite='Lax',
            max_age=int(time_delta.total_seconds()),
        )

        return response


@noauth
class OAuthLogout(aiohttp.web.View):
    async def get(self):
        '''
        ---
        tags:
        - Authentication
        responses:
          "200":
            description: Successfully logged out.
        '''
        _check_if_oauth_feature_available()

        response = aiohttp.web.Response()
        response.del_cookie(name=delivery.jwt.JWT_KEY, path='/')

        return response


@noauth
class OpenIDCfg(aiohttp.web.View):
    '''
    Implements authentication flow according to OpenID specification (see
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    for reference).
    '''
    async def get(self):
        '''
        ---
        tags:
        - Authentication
        produces:
        - application/json
        responses:
          "200":
            description: Successful operation.
            schema:
              $ref: '#/definitions/OpenIdConfig'
        '''
        base_url = self.request.app[consts.APP_BASE_URL]

        return aiohttp.web.json_response(
            data={
                'issuer': base_url,
                'jwks_uri': f'{base_url}/openid/v1/jwks',
                'response_types_supported': [
                    'id_token',
                ],
                'subject_types_supported': [
                    'public',
                ],
                'id_token_signing_alg_values_supported': [
                    algorithm for algorithm in delivery.jwt.Algorithm
                ],
            },
        )


@noauth
class OpenIDJwks(aiohttp.web.View):
    async def get(self):
        '''
        ---
        tags:
        - Authentication
        produces:
        - application/json
        responses:
          "200":
            description: Successful operation.
            schema:
              type: object
              required:
              - keys
              properties:
                keys:
                  type: array
                  items:
                    type: object
        '''
        cfg_factory = self.request.app[consts.APP_CFG_FACTORY]
        delivery_cfg = cfg_factory.delivery(self.request.app[consts.APP_DELIVERY_CFG])
        delivery_cfg = dacite.from_dict(
            data=delivery_cfg.raw,
            data_class=config.DeliveryCfg,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

        import util
        return aiohttp.web.json_response(
            data={
                'keys': [
                    jwt_from_signing_cfg(signing_cfg)
                    for signing_cfg in delivery_cfg.signing_cfgs
                ],
            },
            dumps=util.dict_to_json_factory,
        )


def jwt_from_signing_cfg(signing_cfg: config.SigningCfg) -> delivery.jwt.JSONWebKey:
    algorithm = delivery.jwt.Algorithm(signing_cfg.algorithm.upper())
    use = delivery.jwt.Use.SIGNATURE
    kid = signing_cfg.id

    if algorithm is delivery.jwt.Algorithm.RS256:
        public_key = Crypto.PublicKey.RSA.import_key(signing_cfg.public_key)

        return delivery.jwt.RSAPublicKey(
            use=use,
            kid=kid,
            n=delivery.jwt.encodeBase64urlUInt(public_key.n),
            e=delivery.jwt.encodeBase64urlUInt(public_key.e),
        )
    elif algorithm is delivery.jwt.Algorithm.HS256:
        return delivery.jwt.SymmetricKey(
            use=use,
            kid=kid,
            k=delivery.jwt.encodeBase64url(signing_cfg.private_key.encode('utf-8')),
        )


def auth_middleware(
    signing_cfgs: collections.abc.Iterable[config.SigningCfg],
    default_auth: AuthType=AuthType.BEARER,
) -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        if request.method == 'OPTIONS':
            return await handler(request)

        # auto-generated documentation routes, they are missing the "no-auth" decorator
        if request.path.startswith('/api/v1/doc'):
            return await handler(request)

        auth = getattr(handler, 'auth', default_auth)

        if auth is AuthType.NONE:
            return await handler(request)
        elif auth is AuthType.BEARER:
            pass
        else:
            raise NotImplementedError()

        token = get_token_from_request(request)

        check_jwt_header_content(jwt.get_unverified_header(token))

        issuer = request.app[consts.APP_BASE_URL]

        decoded_jwt = decode_jwt(
            token=token,
            issuer=issuer,
            verify_signature=False,
        )

        signing_cfg = get_signing_cfg_for_key(
            signing_cfgs=signing_cfgs,
            key_id=decoded_jwt.get('key_id'),
        )

        decode_jwt(
            token=token,
            issuer=issuer,
            signing_cfg=signing_cfg,
            verify_signature=True,
        )

        validate_jwt_payload(decoded_jwt)

        subject = decoded_jwt['sub']
        request[consts.REQUEST_GITHUB_USER] = GithubUser(
            username=subject,
            github_hostname=decoded_jwt['github_oAuth']['host'],
        )

        return await handler(request)

    return middleware


def get_signing_cfg_for_key(
    signing_cfgs: collections.abc.Iterable[config.SigningCfg],
    key_id: str | None,
) -> config.SigningCfg:
    if not key_id:
        raise aiohttp.web.HTTPUnauthorized(text='Please specify a key_id')

    for signing_cfg in signing_cfgs:
        if signing_cfg.id == key_id:
            return signing_cfg

    raise aiohttp.web.HTTPUnauthorized(text='key_id is unknown')


def decode_jwt(
    token: str,
    issuer: str,
    signing_cfg=None,
    verify_signature: bool=True,
) -> dict:
    if verify_signature and not signing_cfg:
        raise aiohttp.web.HTTPInternalServerError(text='Error decoding token')

    if signing_cfg:
        json_web_key = jwt_from_signing_cfg(signing_cfg)
    else:
        json_web_key = None

    try:
        return delivery.jwt.decode_jwt(
            token=token,
            verify_signature=verify_signature,
            json_web_key=json_web_key,
            issuer=issuer,
        )
    except (ValueError, jwt.exceptions.DecodeError) as e:
        raise aiohttp.web.HTTPUnauthorized(
            reason='Unauthorized, invalid JWT signature',
            text=str(e),
        )

    except (jwt.exceptions.ExpiredSignatureError) as e:
        raise aiohttp.web.HTTPUnauthorized(
            reason='Unauthorized, token expired',
            text=str(e),
        )

    except (jwt.exceptions.InvalidIssuedAtError) as e:
        raise aiohttp.web.HTTPUnauthorized(
            reason='Bad Request, iat is in future',
            text=str(e),
        )

    except (jwt.exceptions.ImmatureSignatureError) as e:
        raise aiohttp.web.HTTPUnauthorized(
            reason='Bad Request, token not yet valid',
            text=str(e),
        )

    except (jwt.exceptions.InvalidIssuerError) as e:
        raise aiohttp.web.HTTPUnauthorized(
            reason='Unauthorized, issuer not accepted',
            text=str(e),
        )


def check_jwt_header_content(header: dict[str, str]):
    if (typ := header.get('typ', '')).lower() != 'jwt':
        raise aiohttp.web.HTTPUnauthorized(
            text=f'Token type {typ} in header can not be processed',
        )
    if (algorithm := header.get('alg', '')):
        try:
            delivery.jwt.Algorithm(algorithm.upper())
        except ValueError:
            raise aiohttp.web.HTTPNotImplemented(
                text=f'Algorithm {algorithm} is not supported',
            )
    else:
        raise aiohttp.web.HTTPUnauthorized(
            text='Please define an "alg" entry in your token header',
        )


def validate_jwt_payload(decoded_jwt: dict):
    try:
        jsonschema.validate(decoded_jwt, token_payload_schema())
    except jsonschema.exceptions.ValidationError as e:
        raise aiohttp.web.HTTPUnauthorized(text=e.message)

    if (version := decoded_jwt.get('version')) and version != 'v1':
        raise aiohttp.web.HTTPUnauthorized(text='Token version does not match')


def get_token_from_request(request: aiohttp.web.Request) -> str:
    if 'Authorization' in request.headers:
        return _get_token_from_auth_header(request.headers.get('Authorization'))

    return _get_token_from_cookie(request)


def _get_token_from_cookie(request: aiohttp.web.Request) -> str:
    if token := request.cookies.get('bearer_token'):
        return token

    raise aiohttp.web.HTTPUnauthorized(text='Please provide a bearer token in your cookie')


def _get_token_from_auth_header(auth_header: str | None) -> str:
    if not auth_header:
        raise aiohttp.web.HTTPUnauthorized(text='Auth header not set')
    if not auth_header.startswith('Bearer '):
        raise aiohttp.web.HTTPUnauthorized(
            text='Please provide a correctly formatted auth header',
        )

    auth_header_parts = auth_header.split(' ')
    if len(auth_header_parts) != 2:
        raise aiohttp.web.HTTPUnauthorized(text='Auth header malformed')

    return auth_header_parts[1]
