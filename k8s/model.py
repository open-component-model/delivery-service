import dataclasses
import datetime

import kubernetes.client


DOMAIN = 'delivery-gear.gardener.cloud'
LABEL_SERVICE = f'{DOMAIN}/service'


@dataclasses.dataclass(frozen=True)
class Crd:
    DOMAIN: str = DOMAIN
    VERSION: str = 'v1'
    KIND: str = None
    PLURAL_NAME: str = None

    @staticmethod
    def api_version():
        return f'{Crd.DOMAIN}/{Crd.VERSION}'


@dataclasses.dataclass(frozen=True)
class LogCollectionCrd(Crd):
    KIND = 'LogCollection'
    PLURAL_NAME = 'logcollections'


@dataclasses.dataclass(frozen=True)
class BacklogItemCrd(Crd):
    KIND = 'BacklogItem'
    PLURAL_NAME = 'backlogitems'


@dataclasses.dataclass(frozen=True)
class RuntimeArtefactCrd(Crd):
    KIND = 'RuntimeArtefact'
    PLURAL_NAME = 'runtimeartefacts'


@dataclasses.dataclass(frozen=True)
class ContainerStateRunning:
    started_at: datetime.datetime

    @staticmethod
    def from_v1_container_state_running(
        container_state_running: kubernetes.client.V1ContainerStateRunning,
    ) -> 'ContainerStateRunning':
        return ContainerStateRunning(
            started_at=getattr(container_state_running, 'started_at', None),
        )


@dataclasses.dataclass(frozen=True)
class ContainerStateTerminated:
    container_id: str
    exit_code: int
    finished_at: datetime.datetime
    message: str
    reason: str
    signal: int
    started_at: datetime.datetime

    @staticmethod
    def from_v1_container_state_terminated(
        container_state_terminated: kubernetes.client.V1ContainerStateTerminated,
    ) -> 'ContainerStateTerminated':
        return ContainerStateTerminated(
            container_id=getattr(container_state_terminated, 'container_id', None),
            exit_code=getattr(container_state_terminated, 'exit_code', None),
            finished_at=getattr(container_state_terminated, 'finished_at', None),
            message=getattr(container_state_terminated, 'message', None),
            reason=getattr(container_state_terminated, 'reason', None),
            signal=getattr(container_state_terminated, 'signal', None),
            started_at=getattr(container_state_terminated, 'started_at', None),
        )


@dataclasses.dataclass(frozen=True)
class ContainerStateWaiting:
    message: str
    reason: str

    @staticmethod
    def from_v1_container_state_waiting(
        container_state_waiting: kubernetes.client.V1ContainerStateWaiting,
    ) -> 'ContainerStateWaiting':
        return ContainerStateWaiting(
            message=getattr(container_state_waiting, 'message', None),
            reason=getattr(container_state_waiting, 'reason', None),
        )


@dataclasses.dataclass(frozen=True)
class ContainerState:
    running: ContainerStateRunning
    terminated: ContainerStateTerminated#
    waiting: ContainerStateWaiting

    @staticmethod
    def from_v1_container_state(
        container_state: kubernetes.client.V1ContainerState,
    ) -> 'ContainerState':
        return ContainerState(
            running=ContainerStateRunning.from_v1_container_state_running(
                container_state_running=getattr(container_state, 'running', None),
            ),
            terminated=ContainerStateTerminated.from_v1_container_state_terminated(
                container_state_terminated=getattr(container_state, 'terminated', None),
            ),
            waiting=ContainerStateWaiting.from_v1_container_state_waiting(
                container_state_waiting=getattr(container_state, 'waiting', None),
            ),
        )


@dataclasses.dataclass(frozen=True)
class ContainerStatus:
    name: str
    container_id: str
    image: str
    image_id: str
    ready: bool
    last_state: ContainerState
    state: ContainerState

    @staticmethod
    def from_v1_container_status(
        container_status: kubernetes.client.V1ContainerStatus,
    ) -> 'ContainerStatus':
        return ContainerStatus(
            name=container_status.name,
            container_id=container_status.container_id,
            image=container_status.image,
            image_id=container_status.image_id,
            ready=container_status.ready,
            last_state=ContainerState.from_v1_container_state(
                container_state=container_status.last_state,
            ),
            state=ContainerState.from_v1_container_state(
                container_state=container_status.state,
            ),
        )
