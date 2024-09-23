import os


own_dir = os.path.abspath(os.path.dirname(__file__))


def for_os(os_id: str):
    return f'{os.path.join(own_dir, os_id)}.yaml'
