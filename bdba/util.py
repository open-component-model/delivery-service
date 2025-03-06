import urllib.parse


def urljoin(*parts):
    if len(parts) == 1:
        return parts[0]
    first = parts[0]
    last = parts[-1]
    middle = parts[1:-1]

    first = first.rstrip('/')
    middle = list(map(lambda s: s.strip('/'), middle))
    last = last.lstrip('/')

    return '/'.join([first] + middle + [last])


def urlparse(url: str) -> urllib.parse.ParseResult:
    if not '://' in url:
        url = f'x://{url}'

    return urllib.parse.urlparse(url)
