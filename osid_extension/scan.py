import collections.abc
import tarfile

import dacite

import odg.model
import version


def _parse_os_release(
    contents: str
) -> collections.abc.Generator[tuple[str, str], None, None]:
    '''
    parses the contents of an os-release file
    the expected format of contents is a newline-separated list of key=value pairs

        NAME="Alpine Linux"
        ID=alpine
        VERSION_ID=3.21.3
        PRETTY_NAME="Alpine Linux v3.21"
        HOME_URL="https://alpinelinux.org/"
        BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"

    lines starting with '#' are ignored
    each line consists of a key and a value, separated by '='
    values may be enclosed in double quotes
    empty lines are ignored
    '''
    for line in contents.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        name, value = line.split('=', 1)

        yield (name, value.strip('"'))


def _parse_centos_release(
    contents: str
) -> collections.abc.Generator[tuple[str,str], None, None]:
    line = contents.strip()
    if not line or '\n' in line:
        raise ValueError('expected a single non-emtpy line')

    # expected format: "CentOS Linux release <version> (Core)"
    version = line.split(' ')[3]
    yield ('VERSION_ID', version)


def _parse_debian_version(
    contents: str
) -> collections.abc.Generator[tuple[str,str], None, None]:
    line = contents.strip()
    if not line or '\n' in line:
        raise ValueError('expected a single non-emtpy line')

    # file is expected to contain exactly the version
    yield ('VERSION_ID', line)


def determine_osinfo(
    tarfh: tarfile.TarFile
) -> odg.model.OperatingSystemId | None:
    '''
    tries to determine the operating system identification, roughly as specified by
        https://www.freedesktop.org/software/systemd/man/os-release.html
    and otherwise following some conventions believed to be common.

    The argument (an opened tarfile) is being read from its initial position, possibly (but
    not necessarily) to the end. The underlying stream does not need to be seekable.
    It is the caller's responsibility to close the tarfile handle after this function returns.

    The tarfile is expected to contain a directory tree from a "well-known" unix-style operating
    system distribution. In particular, the following (GNU/) Linux distributions are well-supported:
    - alpine
    - debian
    - centos

    In case nothing was recognised within the given tarfile, the returned OperatingSystemId's
    attributes will all be `None`.
    '''
    known_fnames = (
        'debian_version',
        'centos-release',
        'os-release',
    )

    os_info = {}

    for info in tarfh:
        fname = info.name.split('/')[-1]

        if not fname in known_fnames:
            continue

        if info.issym():
            # we assume fnames are the same (this assumption might not always be correct)
            continue

        if not info.isfile():
            continue

        # found an "interesting" file
        contents = tarfh.extractfile(info).read().decode('utf-8')

        if fname == 'os-release':
            for k,v in _parse_os_release(contents):
                if k in os_info:
                    if k == 'VERSION_ID' and version.is_semver_parseable(v) and \
                        not version.is_semver_parseable(os_info[k]):
                        pass
                    else:
                        continue # os-release has lesser precedence
                os_info[k] = v
            if os_info.get('ID') == 'ubuntu' and (ver := os_info.get('VERSION')):
                # of _course_ ubuntu requires a special hack
                os_info['VERSION_ID'] = ver.split(' ', 1)[0]
        elif fname == 'centos-release':
            for k,v in _parse_centos_release(contents):
                os_info[k] = v
        elif fname == 'debian_version':
            for k,v in _parse_debian_version(contents):
                if k in os_info:
                    if not version.is_semver_parseable(v):
                        continue # e.g. ubuntu has "misleading" debian_version
                os_info[k] = v
        else:
            raise NotImplementedError(fname)

    if not os_info:
        return None

    return dacite.from_dict(
        data_class=odg.model.OperatingSystemId,
        data=os_info,
    )
