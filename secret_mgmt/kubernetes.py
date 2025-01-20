import dataclasses


@dataclasses.dataclass
class Kubernetes:
    kubeconfig: dict
