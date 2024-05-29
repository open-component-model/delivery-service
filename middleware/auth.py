import dataclasses
import datetime
import enum
import functools
import logging
import traceback
import urllib.parse
import yaml

import falcon
import jsonschema
import jsonschema.exceptions
import jwt
import requests
import spectree.plugins.falcon_plugin

import ci.util
import delivery.jwt
import model.delivery
import model.github

import ctx_util
import paths

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class RoleMapping:
    name: str
    permissions: list[str]


@dataclasses.dataclass(frozen=True)
class GithubTeamMapping:
    name: str
    roles: list[str]
    host: str


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


class GithubApi:
    def __init__(self, routes: GithubRoutes, oauth_token: str):
        self._routes = routes
        self._oauth_token = oauth_token

    def _get(self, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        headers = kwargs['headers']
        headers['Authorization'] = f'token {self._oauth_token}'

        res = requests.get(*args, **kwargs)
        res.raise_for_status()

        return res

    def current_user(self):
        return self._get(self._routes.current_user()).json()

    def current_user_teams(self):
        return self._get(self._routes.current_user_teams()).json()


class AuthType(enum.Enum):
    NONE = None
    BEARER = 'Bearer'


def noauth(cls):
    '''
    class decorator used to disable authentication for the receiving falcon resource
    '''
    cls.auth = AuthType.NONE
    return cls


@functools.cache
def token_payload_schema():
    return yaml.safe_load(open(paths.token_jsonschema_path, 'rb'))


@functools.cache
def _teams_dict():
    return yaml.safe_load(open(paths.teams_path, 'rb'))['github_team_mappings']


@functools.cache
def _users_dict():
    return yaml.safe_load(open(paths.users_path, 'rb'))['users']


@functools.cache
def _roles_dict():
    return yaml.safe_load(open(paths.roles_path, 'rb'))['roles']


@noauth
class OAuth:
    def __init__(
        self,
        parsed_arguments,
    ):
        self.parsed_arguments = parsed_arguments

    def check_if_oauth_feature_available(self, resp: falcon.Response):
        # Use this function instead of feature checking middleware to prevent
        # circular module imports between middleware.auth.py and features.py
        import features
        feature_authentication = features.get_feature(features.FeatureAuthentication)

        if feature_authentication.state == features.FeatureStates.AVAILABLE:
            return (resp, feature_authentication)
        else:
            resp.complete = True
            resp.status = 400
            resp.media = {
                'error_id': 'feature-inactive',
                'missing_features': [feature_authentication.name]
            }
            return (resp, None)

    def get_auth_cfg(self, feature_authentication):
        auth_cfgs = feature_authentication.oauth_cfgs
        if self.parsed_arguments.add_local_oauth_cfgs:
            additional_cfgs = yaml.safe_load(
                open(
                    self.parsed_arguments.add_local_oauth_cfgs,
                    'rb'
                )
            )['oauth_cfgs']
            auth_cfgs.append(*[model.delivery.OAuth(cfg) for cfg in additional_cfgs])
        return auth_cfgs

    def on_get_cfgs(self, req: falcon.Request, resp: falcon.Response):
        def oauth_cfg_to_dict(oauth_cfg):
            cfg_factory = ctx_util.cfg_factory()
            github_cfg = cfg_factory.github(oauth_cfg.github_cfg())
            github_host = urllib.parse.urlparse(github_cfg.api_url()).hostname.lower()

            endpoints = cfg_factory.delivery_endpoints(self.parsed_arguments.delivery_endpoints)
            if self.parsed_arguments.productive:
                base_url = f'https://{endpoints.service_host()}'
            else:
                base_url = 'http://localhost:5000'
            redirect_uri = ci.util.urljoin(
                base_url,
                'auth',
            ) + '?' + urllib.parse.urlencode({
                'client_id': oauth_cfg.client_id(),
            })

            oauth_url = oauth_cfg.oauth_url().rstrip('?') + '?' + urllib.parse.urlencode({
                'client_id': oauth_cfg.client_id(),
                'scope': oauth_cfg.scope(),
                'redirect_uri': redirect_uri,
            })

            return {
                'name': oauth_cfg.name(),
                'github_name': oauth_cfg.github_cfg(),
                'github_host': github_host,
                'api_url': github_cfg.api_url(),
                'oauth_url': oauth_cfg.oauth_url(),
                'client_id': oauth_cfg.client_id(),
                'scope': oauth_cfg.scope(),
                'redirect_uri': redirect_uri,
                'oauth_url_with_redirect': oauth_url,
            }

        resp, feature_authentication = self.check_if_oauth_feature_available(resp)

        if not feature_authentication:
            return

        resp.media = [oauth_cfg_to_dict(oauth_cfg) for oauth_cfg
            in self.get_auth_cfg(feature_authentication)]

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        resp, feature_authentication = self.check_if_oauth_feature_available(resp)

        if not feature_authentication:
            return

        code = req.params.get('code')
        client_id = req.params.get('client_id')
        access_token = req.params.get('access_token')
        api_url = req.params.get('api_url')

        if not ((access_token and api_url) or (client_id and code)):
            resp.set_header(
                name='WWW-Authenticate',
                value=(
                    'Add either the url query params "code" and "client_id" '
                    'or a valid "access_token" with a github "api_url"'
                ),
            )
            raise falcon.HTTPUnauthorized

        auth_cfgs = self.get_auth_cfg(feature_authentication)
        cfg_factory = ctx_util.cfg_factory()

        if not access_token:
            for oauth_cfg in auth_cfgs:
                if oauth_cfg.client_id() == client_id:
                    break
            else:
                client_ids = [
                    oauth_cfg.client_id() for oauth_cfg in feature_authentication.oauth_cfgs
                ]
                resp.set_header(
                    name='WWW-Authenticate',
                    value=f'no such client: {client_id}; available clients: {client_ids}',
                )
                raise falcon.HTTPUnauthorized

            # exchange code for bearer token
            github_oauth_url = oauth_cfg.token_url() + '?' + \
                urllib.parse.urlencode({
                    'client_id': oauth_cfg.client_id(),
                    'client_secret': oauth_cfg.client_secret(),
                    'code': code,
                })

            res = requests.post(url=github_oauth_url)
            res.raise_for_status()

            parsed = urllib.parse.parse_qs(res.text)

            access_token = parsed.get('access_token')

            if not access_token:
                raise falcon.HTTPInternalServerError(
                    description=f'GitHub api did not return an access token. {parsed}',
                )

            access_token = access_token[0]

            github_cfg: model.github.GithubConfig = cfg_factory.github(oauth_cfg.github_cfg())
            api_url = github_cfg.api_url()
        else:
            api_urls = [
                cfg_factory.github(auth_cfg.github_cfg()).api_url()
                for auth_cfg in auth_cfgs
            ]

            if api_url not in api_urls:
                raise falcon.HTTPUnauthorized

        gh_routes = GithubRoutes(api_url=api_url)
        gh_api = GithubApi(
            routes=gh_routes,
            oauth_token=access_token,
        )

        github_host = urllib.parse.urlparse(api_url).hostname.lower()

        try:
            user = gh_api.current_user()
            team_names = [
                '/'.join((github_host, t['organization']['login'], t['name']))
                for t in gh_api.current_user_teams()
            ]
        except Exception as e:
            logger.warning(f'failed to retrieve user info for {api_url=}: {e}')
            raise falcon.HTTPUnauthorized

        delivery_cfg = ctx_util.cfg_factory().delivery(self.parsed_arguments.delivery_cfg)
        signing_cfgs: list[model.delivery.SigningCfg] = list(delivery_cfg.service().signing_cfgs())

        if not signing_cfgs:
            raise falcon.HTTPInternalServerError('could not retrieve matching signing cfgs')

        # prefer asymmetric signing algorithms before symmetric ones (which don't have a public key)
        signing_cfgs = sorted(
            signing_cfgs,
            key=lambda signing_cfg: 0 if signing_cfg.public_key() else 1,
        )
        signing_cfg = signing_cfgs[0]

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        time_delta = datetime.timedelta(days=730) # 2 years

        token = {
            'version': 'v1',
            'sub': user['login'],
            'iss': 'delivery_service',
            'iat': int(now.timestamp()),
            'github_oAuth': {
                'host': github_host,
                'team_names': team_names,
                'email_address': user.get('email'),
            },
            'exp': int((now + time_delta).timestamp()),
            'key_id': signing_cfg.id(),
        }

        resp.set_cookie(
            name=delivery.jwt.JWT_KEY,
            value=jwt.encode(
                token,
                signing_cfg.secret(),
                algorithm=signing_cfg.algorithm(),
            ),
            http_only=True,
            same_site='Lax',
            max_age=int(time_delta.total_seconds())
        )

        resp.media = token

    def on_get_logout(self, req: falcon.Request, resp: falcon.Response):
        resp, feature_authentication = self.check_if_oauth_feature_available(resp)

        if not feature_authentication:
            return

        resp.unset_cookie(name=delivery.jwt.JWT_KEY, path='/')


@noauth
class OpenID:
    '''
    Implements authentication flow according to OpenID specification (see
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    for reference).
    '''
    def __init__(
        self,
        parsed_arguments,
    ):
        self.parsed_arguments = parsed_arguments

    def on_get_configuration(self, req: falcon.Request, resp: falcon.Response):
        cfg_factory = ctx_util.cfg_factory()

        if self.parsed_arguments.productive:
            endpoints = cfg_factory.delivery_endpoints(self.parsed_arguments.delivery_endpoints)
            base_url = f'https://{endpoints.service_host()}'
        else:
            base_url = 'http://localhost:5000'

        resp.media = {
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
        }

    def on_get_jwks(self, req: falcon.Request, resp: falcon.Response):
        cfg_factory = ctx_util.cfg_factory()

        delivery_cfg = cfg_factory.delivery(self.parsed_arguments.delivery_cfg)
        signing_cfgs: tuple[model.delivery.SigningCfg] = tuple(
            delivery_cfg.service().signing_cfgs()
        )

        resp.media = {
            'keys': [
                delivery.jwt.JSONWebKey.from_signing_cfg(signing_cfg)
                for signing_cfg in signing_cfgs
                if signing_cfg.public_key()
            ],
        }


class Auth:
    def __init__(
        self,
        signing_cfgs,
        default_auth: AuthType = AuthType.BEARER,
    ):
        self.default_auth = default_auth
        self.signing_cfgs = signing_cfgs

    def process_resource(self, req: falcon.Request, resp: falcon.Response, resource, params):
        if req.method == 'OPTIONS':
            return

        auth = getattr(resource, 'auth', self.default_auth)

        # check for req method specific auth type
        method_function = getattr(resource, f'on_{req.method.lower()}', None)
        if method_function:
            auth = getattr(method_function, 'auth', auth)

        # auto-generated documentation routes, they are missing the "no-auth" decorator
        if isinstance(
            resource,
            (spectree.plugins.falcon_plugin.DocPage, spectree.plugins.falcon_plugin.OpenAPI),
        ):
            return

        if auth is AuthType.NONE:
            return
        elif auth is AuthType.BEARER:
            pass
        else:
            raise NotImplementedError()

        token = get_token_from_request(req)

        check_jwt_header_content(jwt.get_unverified_header(token))

        decoded_jwt = decode_jwt(token=token, verify_signature=False)

        signing_cfg = get_signing_cfg_for_key(self.signing_cfgs, decoded_jwt.get('key_id'))

        decode_jwt(token=token, signing_cfg=signing_cfg, verify_signature=True)

        validate_jwt_payload(decoded_jwt)

        subject = decoded_jwt['sub']
        req.context['github_user'] = GithubUser(
            username=subject,
            github_hostname=decoded_jwt['github_oAuth']['host'],
        )

        github_oAuth = decoded_jwt.get('github_oAuth')

        if github_oAuth:
            req.context['user_permissions'] = get_permissions_for_github_oAuth(github_oAuth)
        else:
            req.context['user_permissions'] = get_user_permissions(subject)


def get_permissions_for_github_oAuth(github_oAuth: dict) -> set[str]:
    '''
    we expect github oAuth to be a dict:

        {
            team_names: list[str]
            host: str
        }
    '''
    def permissions(github_oAuth):
        for team_name in github_oAuth.get('team_names'):
            if (team_mapping := _github_team_mapping(team_name, github_oAuth.get('host'))):
                for role_name in team_mapping.roles:
                    yield from _role_mapping(role_name).permissions

    return {permission for permission in permissions(github_oAuth)}


def get_user_permissions(
    user_name: str,
    raise_if_absent: falcon.HTTPError = falcon.HTTPUnauthorized,
) -> set[str]:
    def permissions(user_dict):
        for role_name in user_dict['roles']:
            yield from _role_mapping(role_name=role_name).permissions

    for user_dict in _users_dict():
        if user_dict.get('name') == user_name:
            return {permission for permission in permissions(user_dict=user_dict)}

    if raise_if_absent:
        raise raise_if_absent()

    return set()


def get_signing_cfg_for_key(
    signing_cfgs: list[model.delivery.SigningCfg],
    key_id: str | None,
) -> model.delivery.SigningCfg:
    if not key_id:
        raise falcon.HTTPUnauthorized(description='please specify a key_id')

    for signing_cfg in signing_cfgs:
        if signing_cfg.id() == key_id:
            return signing_cfg

    raise falcon.HTTPUnauthorized(description='key_id is unknown')


def decode_jwt(token, signing_cfg=None, verify_signature: bool = True) -> dict:
    if verify_signature and not signing_cfg:
        raise falcon.HTTPInternalServerError('error decoding token')

    if signing_cfg:
        json_web_key = delivery.jwt.JSONWebKey.from_signing_cfg(signing_cfg)
    else:
        json_web_key = None

    try:
        return delivery.jwt.decode_jwt(
            token=token,
            verify_signature=verify_signature,
            json_web_key=json_web_key,
            issuer='delivery_service',
        )
    except (ValueError, jwt.exceptions.DecodeError) as e:
        raise falcon.HTTPUnauthorized(
            title='Unauthorized, invalid JWT signature',
            description=traceback.format_exception(e),
        )

    except (jwt.exceptions.ExpiredSignatureError) as e:
        raise falcon.HTTPUnauthorized(
            title='Unauthorized, token expired',
            description=traceback.format_exception(e),
        )

    except (jwt.exceptions.InvalidIssuedAtError) as e:
        raise falcon.HTTPBadRequest(
            title='Bad Request, iat is in future',
            description=traceback.format_exception(e),
        )

    except (jwt.exceptions.ImmatureSignatureError) as e:
        raise falcon.HTTPBadRequest(
            title='Bad Request, token not yet valid',
            description=traceback.format_exception(e),
        )

    except (jwt.exceptions.InvalidIssuerError) as e:
        raise falcon.HTTPUnauthorized(
            title='Unauthorized, issuer not accepted',
            description=traceback.format_exception(e),
        )


def check_jwt_header_content(header: dict[str, str]):
    if (typ := header.get('typ', '')).lower() != 'jwt':
        raise falcon.HTTPUnauthorized(
            description=f'token type {typ} in header can not be processed',
        )
    if (algorithm := header.get('alg', '')):
        try:
            delivery.jwt.Algorithm(value=algorithm.upper())
        except ValueError:
            raise falcon.HTTPNotImplemented(
                description=f'algorithm {algorithm} is not supported',
            )
    else:
        raise falcon.HTTPBadRequest(
            description='please define an "alg" entry in your token header',
        )


def validate_jwt_payload(decoded_jwt: dict):
    try:
        jsonschema.validate(decoded_jwt, token_payload_schema())
    except jsonschema.exceptions.ValidationError as e:
        raise falcon.HTTPBadRequest(description=e.message)

    if (version := decoded_jwt.get('version')) and version != 'v1':
        raise falcon.HTTPBadRequest(description='token version does not match')


def get_token_from_request(req: falcon.Request) -> str:
    if req.auth:
        token = _get_token_from_auth_header(req.auth)
    else:
        token = _get_token_from_cookie(req)

    return token


def _get_token_from_cookie(req: falcon.Request) -> str:
    if (cookie_list := req.get_cookie_values('bearer_token')):
        return cookie_list[0]

    raise falcon.HTTPBadRequest(description='please provide a bearer token in your cookie')


def _get_token_from_auth_header(auth_header) -> str:
    if not auth_header:
        raise falcon.HTTPBadRequest(description='auth header not set')
    if not auth_header.startswith('Bearer '):
        raise falcon.HTTPBadRequest(
            description='please provide a correctly formatted auth header'
        )

    auth_header_parts = auth_header.split(' ')
    if len(auth_header_parts) != 2:
        raise falcon.HTTPBadRequest(description='auth header malformed')

    return auth_header_parts[1]


@functools.cache
def _github_team_mapping(team_name: str, host: str) -> GithubTeamMapping | None:
    for team_dict in _teams_dict():
        if team_dict.get('name') == team_name and host == team_dict.get('host'):
            return GithubTeamMapping(**team_dict)


@functools.cache
def _role_mapping(role_name: str) -> RoleMapping:
    for roles_dict in _roles_dict():
        if roles_dict['name'] == role_name:
            return RoleMapping(**roles_dict)

    raise RuntimeError(f'no such role {role_name}')
