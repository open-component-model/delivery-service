import dataclasses


@dataclasses.dataclass
class SigningCfg:
    id: str
    private_key: str
    public_key: str
    algorithm: str
    priority: int = 0 # lower value means lower priority (useful e.g. for rotation)
