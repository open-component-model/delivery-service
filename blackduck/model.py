import dataclasses


@dataclasses.dataclass
class Project:
    name: str
    project_group: str
    description: str = None


@dataclasses.dataclass
class ProjectGroup:
    name: str
    description: str = None
