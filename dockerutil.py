import base64
import json
import os

import util


def prepare_docker_cfg(
    image_reference: str,
    username: str,
    password: str,
):
    hostname = util.urlparse(image_reference).hostname

    auth_str = f'{username}:{password}'
    encoded_auth_str = base64.b64encode(auth_str.encode()).decode()

    docker_cfg = {
        'auths': {
            hostname: {
                'auth': encoded_auth_str,
            },
        },
    }

    docker_cfg_path = os.path.join(
        os.environ['HOME'],
        '.docker',
        'config.json',
    )
    docker_cfg_dir = os.path.dirname(docker_cfg_path)
    os.makedirs(docker_cfg_dir, exist_ok=True)
    with open(docker_cfg_path, 'w') as f:
        json.dump(docker_cfg, f)
