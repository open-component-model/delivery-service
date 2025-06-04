import collections.abc
import dataclasses
import datetime
import enum
import functools
import logging
import re
import urllib.parse
import uuid

import aiohttp
import aiohttp.typedefs
import aiohttp.web
import Crypto.PublicKey.RSA
import jsonschema
import jsonschema.exceptions
import jwt
import sqlalchemy.orm
import sqlalchemy.ext.asyncio as sqlasync
import yaml

import delivery.jwt

import consts
import ctx_util
import deliverydb.model as dm
import lookups
import paths
import secret_mgmt.oauth_cfg
import secret_mgmt.rbac
import secret_mgmt.signing_cfg
import util


logger = logging.getLogger(__name__)

SESSION_TOKEN_MAX_AGE = datetime.timedelta(minutes=5)
REFRESH_TOKEN_MAX_AGE = datetime.timedelta(days=183)


@dataclasses.dataclass(frozen=True)
class GithubUser():
    username: str
    github_hostname: str
    type: str = 'github-user'


class GithubRoutes:
    def __init__(self, api_url: str):
        self.api_url = api_url

    def _url(self, *parts):
        return util.urljoin(
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
    def __init__(
        self,
        api_url: str,
        access_token: str,
    ):
        self._routes = GithubRoutes(api_url=api_url)
        self._access_token = access_token
        self.session = aiohttp.ClientSession()

    async def _get(self, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        headers = kwargs['headers']
        headers['Authorization'] = f'token {self._access_token}'

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
        def oauth_cfg_to_dict(oauth_cfg: secret_mgmt.oauth_cfg.OAuthCfg):
            github_host = urllib.parse.urlparse(oauth_cfg.api_url).hostname.lower()

            redirect_uri = util.urljoin(
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
                'github_host': github_host,
                'api_url': oauth_cfg.api_url,
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


def find_github_oauth_cfg(
    oauth_cfgs: collections.abc.Iterable[secret_mgmt.oauth_cfg.OAuthCfg],
    api_url: str | None=None,
    client_id: str | None=None,
) -> secret_mgmt.oauth_cfg.OAuthCfg:
    if not (bool(api_url) ^ bool(client_id)):
        raise ValueError('exactly one of `api_url` and `client_id` must be provided')

    filtered_oauth_cfgs = [
        oauth_cfg for oauth_cfg in oauth_cfgs
        if oauth_cfg.type is secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB
    ]

    if api_url:
        for oauth_cfg in filtered_oauth_cfgs:
            if oauth_cfg.api_url == api_url:
                return oauth_cfg

        api_urls = [oauth_cfg.api_url for oauth_cfg in filtered_oauth_cfgs]
        raise aiohttp.web.HTTPUnauthorized(
            headers={
                'WWW-Authenticate': f'no such api-url: {api_url}; available api-urls: {api_urls}',
            },
        )

    for oauth_cfg in filtered_oauth_cfgs:
        if oauth_cfg.client_id == client_id:
            return oauth_cfg

    client_ids = [oauth_cfg.client_id for oauth_cfg in filtered_oauth_cfgs]
    raise aiohttp.web.HTTPUnauthorized(
        headers={
            'WWW-Authenticate': f'no such client: {client_id}; available clients: {client_ids}',
        },
    )


def find_signing_cfg(
    signing_cfgs: collections.abc.Iterable[secret_mgmt.signing_cfg.SigningCfg],
) -> secret_mgmt.signing_cfg.SigningCfg:
    if not signing_cfgs:
        raise aiohttp.web.HTTPInternalServerError(text='could not retrieve signing cfgs')

    return max(signing_cfgs, key=lambda cfg: cfg.priority)


async def find_github_user_identifier(
    oauth_cfg: secret_mgmt.oauth_cfg.OAuthCfg,
    github_access_token: str | None=None,
    github_code: str | None=None,
) -> dm.GitHubUserIdentifier:
    if github_code:
        github_token_url = oauth_cfg.token_url + '?' + urllib.parse.urlencode({
            'client_id': oauth_cfg.client_id,
            'client_secret': oauth_cfg.client_secret,
            'code': github_code,
        })

        async with aiohttp.ClientSession() as session:
            async with session.post(url=github_token_url) as res:
                res.raise_for_status()

                parsed = urllib.parse.parse_qs(await res.text())
                github_access_token = parsed['access_token'][0]

    elif not github_access_token:
        raise ValueError('either a `github_code` or an `github_access_token` must be provided')

    gh_api = GithubApi(
        api_url=oauth_cfg.api_url,
        access_token=github_access_token,
    )

    try:
        user = await gh_api.current_user()
    except Exception as e:
        logger.warning(f'failed to retrieve user info for {oauth_cfg.api_url=}: {e}')
        raise aiohttp.web.HTTPUnauthorized
    finally:
        await gh_api.close_connection()

    return dm.GitHubUserIdentifier(
        username=user['login'],
        email_address=user['email'],
        hostname=urllib.parse.urlparse(oauth_cfg.api_url).hostname.lower(),
    )


def find_role_bindings(
    oauth_cfg: secret_mgmt.oauth_cfg.OAuthCfg,
    username: str,
) -> collections.abc.Iterable[dm.RoleBinding]:
    if oauth_cfg.type is secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB:
        github_api_lookup = lookups.github_api_lookup()
        github_host = urllib.parse.urlparse(oauth_cfg.api_url).hostname.lower()

        def find_github_subject(
            subjects: list[secret_mgmt.oauth_cfg.Subject],
        ) -> secret_mgmt.oauth_cfg.Subject | None:
            for subject in subjects:
                if subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_USER:
                    if subject.name == username:
                        return subject

                elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_ORG:
                    github_org = util.urljoin(github_host, subject.name)
                    github_api = github_api_lookup(github_org)

                    organisation = github_api.organization(subject.name)
                    for member in organisation.members():
                        if member.login == username:
                            return subject

                elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_TEAM:
                    org_name, team_name = subject.name.split('/')
                    github_org = util.urljoin(github_host, org_name)
                    github_api = github_api_lookup(github_org)

                    organisation = github_api.organization(org_name)
                    team = organisation.team_by_name(team_name)
                    for member in team.members():
                        if member.login == username:
                            return subject

        for role_binding in oauth_cfg.role_bindings:
            if not (subject := find_github_subject(subjects=role_binding.subjects)):
                continue

            github_username = None
            github_organisation = None
            github_team = None
            if subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_USER:
                github_username = subject.name
            elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_ORG:
                github_organisation = subject.name
            elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_TEAM:
                github_team = subject.name

            yield from (
                dm.RoleBinding(
                    name=role,
                    origin=dm.GitHubRoleBindingOrigin(
                        hostname=github_host,
                        organisation=github_organisation,
                        team=github_team,
                        username=github_username,
                    )
                ) for role in role_binding.roles
            )

    else:
        raise ValueError(f'unsupported {oauth_cfg.type=}')


def build_refresh_token_payload(
    user_id: str,
    refresh_token_identifier: str,
    separator: str='|',
) -> str:
    return f'{user_id}{separator}{refresh_token_identifier}'


def parse_refresh_token_payload(
    refresh_token_payload: str,
    separator: str='|',
) -> tuple[str, str]:
    return refresh_token_payload.split(separator)


async def set_session_and_refresh_token(
    user_id: str,
    issuer: str,
    db_session: sqlasync.session.AsyncSession,
    existing_refresh_token_identifier: str | None=None,
    signing_cfg: secret_mgmt.signing_cfg.SigningCfg | None=None,
) -> aiohttp.web.Response:
    if not signing_cfg:
        secret_factory = ctx_util.secret_factory()
        signing_cfg = find_signing_cfg(
            signing_cfgs=secret_factory.signing_cfg(),
        )

    if not (user := await db_session.get(dm.User, user_id)):
        raise aiohttp.web.HTTPUnauthorized(text=f'Did not find user with {user_id=}')

    if not (role_bindings := user.role_bindings):
        raise aiohttp.web.HTTPUnauthorized(text='User is not authorised to access this service')

    refresh_tokens = list(user.refresh_tokens)

    if existing_refresh_token_identifier is not None:
        # check if provided refresh token is valid and if so, remove it from list of persisted tokens
        # -> user will get a new refresh token
        for refresh_token in refresh_tokens:
            if refresh_token['identifier'] == existing_refresh_token_identifier:
                refresh_tokens.remove(refresh_token)
                break
        else:
            raise aiohttp.web.HTTPUnauthorized(text='The provided refresh token is not valid')

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    refresh_token_identifier = str(uuid.uuid4())

    refresh_tokens.append({
        'identifier': refresh_token_identifier,
        'exp': int((now + REFRESH_TOKEN_MAX_AGE).timestamp()),
    })

    # remove already expired refresh tokens
    user.refresh_tokens = [
        refresh_token for refresh_token in refresh_tokens
        if datetime.datetime.fromtimestamp(
            timestamp=refresh_token['exp'],
            tz=datetime.timezone.utc,
        ) > now
    ]

    db_session.add(user)
    await db_session.commit()

    session_token = {
        'version': 'v1',
        'iss': issuer,
        'iat': int(now.timestamp()),
        'exp': int((now + SESSION_TOKEN_MAX_AGE).timestamp()),
        'key_id': signing_cfg.id,
        'sub': user_id,
        'roles': list({
            role_binding['name'] for role_binding in role_bindings
        }),
    }

    response = aiohttp.web.json_response(
        data=session_token,
    )

    response.set_cookie(
        name=delivery.jwt.JWT_KEY,
        value=jwt.encode(
            session_token,
            signing_cfg.private_key,
            algorithm=signing_cfg.algorithm,
        ),
        httponly=True,
        samesite='Lax',
        max_age=int(SESSION_TOKEN_MAX_AGE.total_seconds()),
    )

    refresh_token_payload = build_refresh_token_payload(
        user_id=user_id,
        refresh_token_identifier=refresh_token_identifier,
    )

    response.set_cookie(
        name=delivery.jwt.REFRESH_TOKEN_KEY,
        value=refresh_token_payload,
        httponly=True,
        samesite='Lax',
        max_age=int(REFRESH_TOKEN_MAX_AGE.total_seconds()),
    )

    return response


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

        issuer = self.request.app[consts.APP_BASE_URL]
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        params = self.request.rel_url.query
        code = util.param(params, 'code')
        client_id = util.param(params, 'client_id')
        access_token = util.param(params, 'access_token')
        api_url = util.param(params, 'api_url')

        if (access_token and api_url) or (client_id and code):
            idp_type = secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB

        else:
            raise aiohttp.web.HTTPUnauthorized(
                headers={
                    'WWW-Authenticate': (
                        'Add either the url query params "code" and "client_id" '
                        'or a valid "access_token" with a github "api_url"'
                    ),
                },
            )

        if idp_type is secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB:
            oauth_cfg = find_github_oauth_cfg(
                oauth_cfgs=feature_authentication.oauth_cfgs,
                api_url=api_url,
                client_id=client_id,
            )

            user_identifier = await find_github_user_identifier(
                oauth_cfg=oauth_cfg,
                github_access_token=access_token,
                github_code=code,
            )

        else:
            raise aiohttp.web.HTTPUnauthorized(text=f'Unsupported {idp_type=}')

        user_idp = await db_session.get(dm.UserIdentifiers, {
            'type': idp_type,
            'identifier_normalised_digest': user_identifier.normalised_digest,
        })

        if user_idp:
            user_id = user_idp.user_id
        else:
            user_id = str(uuid.uuid4())

            role_bindings = set(find_role_bindings(
                oauth_cfg=oauth_cfg,
                username=user_identifier.username,
            ))

            try:
                db_session.add(dm.User(
                    id=user_id,
                    role_bindings=util.dict_serialisation(role_bindings),
                    refresh_tokens=[],
                ))
                db_session.add(dm.UserIdentifiers(
                    user_id=user_id,
                    type=idp_type,
                    identifier=util.dict_serialisation(user_identifier),
                    identifier_normalised_digest=user_identifier.normalised_digest,
                ))
                await db_session.commit()
            except:
                await db_session.rollback()
                raise

        return await set_session_and_refresh_token(
            user_id=user_id,
            issuer=issuer,
            db_session=db_session,
        )


@noauth
class OAuthRefresh(aiohttp.web.View):
    async def post(self):
        issuer = self.request.app[consts.APP_BASE_URL]
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        refresh_token = self.request.cookies.get(delivery.jwt.REFRESH_TOKEN_KEY)

        if not refresh_token:
            raise aiohttp.web.HTTPUnauthorized(
                text='Please provide a refresh token in your cookie',
            )

        user_id, refresh_token_identifier = parse_refresh_token_payload(refresh_token)

        return await set_session_and_refresh_token(
            user_id=user_id,
            issuer=issuer,
            db_session=db_session,
            existing_refresh_token_identifier=refresh_token_identifier,
        )


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

        refresh_token = self.request.cookies.get(delivery.jwt.REFRESH_TOKEN_KEY)

        response = aiohttp.web.Response()
        response.del_cookie(name=delivery.jwt.JWT_KEY, path='/')
        response.del_cookie(name=delivery.jwt.REFRESH_TOKEN_KEY, path='/')

        if not refresh_token:
            return response

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        user_id, refresh_token_identifier = parse_refresh_token_payload(refresh_token)

        if not (user := await db_session.get(dm.User, user_id)):
            raise aiohttp.web.HTTPUnauthorized(text=f'Did not find user with {user_id=}')

        user.refresh_tokens = [
            refresh_token for refresh_token in user.refresh_tokens
            if refresh_token['identifier'] != refresh_token_identifier
        ]
        db_session.add(user)
        await db_session.commit()

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
        secret_factory = self.request.app[consts.APP_SECRET_FACTORY]

        import util
        return aiohttp.web.json_response(
            data={
                'keys': [
                    jwt_from_signing_cfg(signing_cfg)
                    for signing_cfg in secret_factory.signing_cfg()
                ],
            },
            dumps=util.dict_to_json_factory,
        )


def jwt_from_signing_cfg(
    signing_cfg: secret_mgmt.signing_cfg.SigningCfg,
) -> delivery.jwt.JSONWebKey:
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
    signing_cfgs: collections.abc.Iterable[secret_mgmt.signing_cfg.SigningCfg],
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

        secret_factory = request.app[consts.APP_SECRET_FACTORY]

        try:
            rbac_cfgs = secret_factory.rbac()
            if len(rbac_cfgs) != 1:
                raise ValueError(f'There must be exactly one rbac secret, found {len(rbac_cfgs)}')
            role_bindings = rbac_cfgs[0]
        except secret_mgmt.SecretTypeNotFound:
            role_bindings = secret_mgmt.rbac.RoleBindings() # use default rbac cfg

        user_role_names = decoded_jwt.get('roles', [])

        user_permissions = _iter_user_permissions(
            user_role_names=user_role_names,
            role_bindings=role_bindings,
        )

        _raise_on_missing_permissions(
            user_permissions=user_permissions,
            route=request.path,
            method=request.method,
        )

        subject = decoded_jwt['sub']
        request[consts.REQUEST_GITHUB_USER] = GithubUser(
            username=subject,
            github_hostname=decoded_jwt['github_oAuth']['host'],
        )
        request[consts.REQUEST_USER_ROLES] = user_role_names

        return await handler(request)

    return middleware


def _iter_user_permissions(
    user_role_names: collections.abc.Sequence[str],
    role_bindings: secret_mgmt.rbac.RoleBindings,
) -> collections.abc.Generator[secret_mgmt.rbac.Permission, None, None]:
    for role in role_bindings.filter_roles(names=user_role_names):
        for permission_name in role.permissions:
            if permission := role_bindings.find_permission(
                name=permission_name,
                absent_ok=True,
            ):
                yield permission
                continue

            # raise 401 -> delivery-dashboard will require the user to re-authenticate
            raise aiohttp.web.HTTPUnauthorized(
                text=(
                    f'did not find permission with {permission_name=}, this means there is a '
                    'configuration error, please check the role definitions or contact an admin'
                ),
            )


def _raise_on_missing_permissions(
    user_permissions: collections.abc.Iterable[secret_mgmt.rbac.Permission],
    route: str,
    method: str,
):
    '''
    If the `user_permissions` do not grant the necessary permissions to use the `method` for the
    `route`, this function will raise a HTTP 403 forbidden exception.
    '''
    for user_permission in user_permissions:
        for permission_route in user_permission.routes:
            if re.fullmatch(permission_route, route):
                break
        else:
            continue # `user_permission` does not grant access to `route`

        for permission_method in user_permission.methods:
            if re.fullmatch(permission_method, method, re.IGNORECASE):
                break
        else:
            continue # `user_permission` does not grant access to `route` via `method`

        return # user has required permissions

    raise aiohttp.web.HTTPForbidden(
        text=f'User is not allowed to perform the {method=} for {route=}',
    )


class Rbac(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description:
          Returns a list of all available roles and permissions.
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
              - roles
              - permissions
              properties:
                roles:
                  type: array
                  items:
                    type: object
                    required:
                    - name
                    - permissions
                    properties:
                      name:
                        type: string
                      permissions:
                        type: array
                        items:
                          type: string
                permissions:
                  type: array
                  items:
                    type: object
                    required:
                    - name
                    - routes
                    - methods
                    properties:
                      name:
                        type: string
                      routes:
                        type: array
                        items:
                          type: string
                      methods:
                        type: array
                        items:
                          type: string
        '''
        secret_factory = self.request.app[consts.APP_SECRET_FACTORY]

        try:
            rbac_cfgs = secret_factory.rbac()
            if len(rbac_cfgs) != 1:
                raise ValueError(f'There must be exactly one rbac secret, found {len(rbac_cfgs)}')
            role_bindings = rbac_cfgs[0]
        except secret_mgmt.SecretTypeNotFound:
            role_bindings = secret_mgmt.rbac.RoleBindings() # use default rbac cfg

        return aiohttp.web.json_response(
            data=role_bindings,
            dumps=util.dict_to_json_factory,
        )


class User(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description:
          Returns information for the authenticated user, e.g. a list of the assigned roles and
          granted permissions.
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
              - roles
              - permissions
              properties:
                id:
                  type: string
                identifiers:
                  type: array
                  items:
                    type: object
                    required:
                    - type
                    - identifier
                    properties:
                      type:
                        type: string
                      identifier:
                        type: object
                        required:
                        - username
                        properties:
                          username:
                            type: string
                          email_address:
                            type: string
                          hostname:
                            type: string
                roles:
                  type: array
                  items:
                    type: object
                    required:
                    - name
                    - permissions
                    properties:
                      name:
                        type: string
                      permissions:
                        type: array
                        items:
                          type: string
                permissions:
                  type: array
                  items:
                    type: object
                    required:
                    - name
                    - routes
                    - methods
                    properties:
                      name:
                        type: string
                      routes:
                        type: array
                        items:
                          type: string
                      methods:
                        type: array
                        items:
                          type: string
        '''
        secret_factory = self.request.app[consts.APP_SECRET_FACTORY]
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        user_id = self.request[consts.REQUEST_USER_ID]
        user_role_names = self.request[consts.REQUEST_USER_ROLES]

        try:
            rbac_cfgs = secret_factory.rbac()
            if len(rbac_cfgs) != 1:
                raise ValueError(f'There must be exactly one rbac secret, found {len(rbac_cfgs)}')
            role_bindings = rbac_cfgs[0]
        except secret_mgmt.SecretTypeNotFound:
            role_bindings = secret_mgmt.rbac.RoleBindings() # use default rbac cfg

        user_roles = role_bindings.filter_roles(names=user_role_names)

        user_permissions = _iter_user_permissions(
            user_role_names=user_role_names,
            role_bindings=role_bindings,
        )

        user = await db_session.get(
            dm.User,
            user_id,
            options=(sqlalchemy.orm.selectinload(dm.User.identifiers),),
        )

        if not user:
            raise aiohttp.web.HTTPUnauthorized(text=f'Did not find user with {user_id=}')

        return aiohttp.web.json_response(
            data={
                'id': user.id,
                'identifiers': [
                    {
                        'type': user_identifier.type,
                        'identifier': user_identifier.identifier,
                    } for user_identifier in user.identifiers
                ],
                'roles': user_roles,
                'permissions': user_permissions,
            },
            dumps=util.dict_to_json_factory,
        )


def get_signing_cfg_for_key(
    signing_cfgs: collections.abc.Iterable[secret_mgmt.signing_cfg.SigningCfg],
    key_id: str | None,
) -> secret_mgmt.signing_cfg.SigningCfg:
    if not key_id:
        raise aiohttp.web.HTTPUnauthorized(text='Please specify a key_id')

    for signing_cfg in signing_cfgs:
        if signing_cfg.id == key_id:
            return signing_cfg

    raise aiohttp.web.HTTPUnauthorized(text='key_id is unknown')


def decode_jwt(
    token: str,
    issuer: str,
    signing_cfg: secret_mgmt.signing_cfg.SigningCfg=None,
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
