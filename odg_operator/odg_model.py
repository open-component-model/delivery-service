import dataclasses
import enum


class ManagedResourceClasses(enum.StrEnum):
    INTERNAL = 'internal'
    EXTERNAL = 'external'


class ExtensionTypes(enum.StrEnum):
    DELIVERY_SERVICE = 'delivery-service'
    DELIVERY_DASHBOARD = 'delivery-dashboard'
    DELIVERY_DB = 'delivery-db'
    MALWARE_SCANNER = 'malware-scanner'
    ARTEFACT_ENUMERATOR = 'artefact-enumerator'
    BACKLOG_CONTROLLER = 'backlog-controller'
    INGRESS_NGINX = 'ingress-nginx'
    SAST = 'sast'
    CRYPTO = 'crypto'
    BDBA = 'bdba'


@dataclasses.dataclass
class ManagedResourceMeta:
    group: str = 'resources.gardener.cloud'
    version: str = 'v1alpha1'
    plural: str = 'managedresources'
    kind: str = 'ManagedResource'

    @staticmethod
    def apiVersion() -> str:
        return f'{ManagedResourceMeta.group}/{ManagedResourceMeta.version}'


@dataclasses.dataclass
class ODGExtensionMeta:
    group: str = 'open-delivery-gear.ocm.software'
    version: str = 'v1'
    plural: str = 'odges'
    kind: str = 'ODGE'

    @staticmethod
    def apiVersion() -> str:
        return f'{ODGExtensionMeta.group}/{ODGExtensionMeta.version}'


@dataclasses.dataclass
class ODGMeta:
    group: str = 'open-delivery-gear.ocm.software'
    version: str = 'v1'
    plural: str = 'odgs'
    kind: str = 'ODG'

    @staticmethod
    def apiVersion() -> str:
        return f'{ODGMeta.group}/{ODGMeta.version}'


@dataclasses.dataclass
class Extension:
    type: ExtensionTypes
    base_url: str
    helm_values_path: str = None # defaults to extension type
    ocm_node_name: str = None # defaults to extension type

    def __post_init__(self):
        if not self.helm_values_path:
            self.helm_values_path = str(self.type)

        if not self.ocm_node_name:
            self.ocm_node_name = str(self.type)

    def helm_values(self, namespace: str) -> dict:
        return {
            'target_namespace': namespace,
            str(self.type): {
                'enabled': True,
            }
        }


@dataclasses.dataclass(kw_only=True)
class DeliveryService(Extension):
    hostnames: list[str]
    startup_args: list[str] = dataclasses.field(default_factory=list)

    def helm_values(self, namespace: str):
        return {
            'ingress': {
                'hosts': self.hostnames,
            },
            'args': self.startup_args,
            'target_namespace': namespace,
        }


@dataclasses.dataclass(kw_only=True)
class NginxIngress(Extension):

    def helm_values(self, namespace: str):
        return {
            'namespaceOverride': namespace,
            'externalTrafficPolicy': 'Cluster',
            'controller': {
                'metrics': {
                    'enabled': True,
                },
                'podAnnotations': {
                    'prometheus.io/scrape': True,
                    'prometheus.io/port': '10254',
                }
            }
        }


@dataclasses.dataclass(kw_only=True)
class DeliveryDB(Extension):
    postgres_password: str
    oci_image_tag: str = '16.0.0' # TODO: read oci-ref from ocm

    def helm_values(self, namespace: str):
        return {
            'fullnameOverride': 'delivery-db',
            'namespaceOverride': namespace,
            'image': {
                'tag': self.oci_image_tag,
            },
            'auth': {
                'postgresPassword': self.postgres_password,
            },
        }


@dataclasses.dataclass(kw_only=True)
class DeliveryDashboard(Extension):
    hostnames: list[str]
    delivery_service_url: str

    def helm_values(self, namespace: str):
        return {
            'ingress': {
                'hosts': self.hostnames,
            },
            'envVars': {
                'REACT_APP_DELIVERY_SERVICE_API_URL': self.delivery_service_url, # noqa: E501
            },
            'target_namespace': namespace,
        }


@dataclasses.dataclass
class ODG:
    name: str
    target_namespace: str
    origin_namespace: str
    extensions: list[Extension]
    component_version: str
    component_name: str = 'ocm.software/ocm-gear'
