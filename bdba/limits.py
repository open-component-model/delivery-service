'''
(character) limits for BDBA-api

limits are either found by trail and error or from the documentation
'''

app_name = 255
file_name = 241


def fits(
    value: str,
    /,
    limit: int,
) -> bool:
    return len(value) <= limit


def trim(
    value: str,
    /,
    limit: int,
) -> str:
    return value[:limit]
