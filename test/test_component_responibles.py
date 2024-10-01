import unittest.mock

import pytest

import github.codeowners

import responsibles
import responsibles.user_model


@pytest.fixture()
def gh_api():
    def create_user_mock(username: str):
        user_mock = unittest.mock.Mock()
        if username.lower() == 'thelegend27':
            user_mock.login = 'thelegend27'
            user_mock.email = 'thelegend27@mail.foo'
            user_mock.name = 'The Legend 27'
            user_mock.html_url = 'https://github.foo.bar/thelegend27'
        elif username == 'darthvader':
            user_mock.login = 'darthvader'
            user_mock.email = 'darthvader@mail.foo'
            user_mock.name = 'Darth Vader'
            user_mock.html_url = 'https://github.foo.bar/darthvader'

        return user_mock

    def create_member_mock():
        return [create_user_mock('TheLegend27')]

    api_mock = unittest.mock.Mock()
    org_mock = unittest.mock.Mock()
    team_mock = unittest.mock.Mock()

    team_mock.members = create_member_mock

    org_mock.team_by_name.return_value = team_mock

    api_mock.organization.return_value = org_mock
    api_mock._github_url = 'https://github.foo.bar/org/repo'
    api_mock.user = create_user_mock

    return api_mock


@pytest.fixture()
def meta_origin():
    return responsibles.user_model.MetaOrigin(
        source='https://github.foo.bar/org/repo',
        originType='github-codeowners-file',
        type='metaOrigin',
    )


@pytest.fixture()
def repo():
    mock = unittest.mock.Mock()
    mock.html_url = 'https://github.foo.bar/org/repo'
    return mock


def user_identities(
    codeowners: str,
    gh_api,
    repo,
) -> tuple[responsibles.user_model.UserIdentity]:
    codeowners_gen = (
        github.codeowners.parse_codeowner_entry(
            entry=entry,
        )
        for entry in github.codeowners.filter_codeowners_entries(
            codeowners.split('\n')
        )
    )
    flattend_codeowners = responsibles.flatten_codeowners(
        codeowner_entries=codeowners_gen,
        gh_api=gh_api,
    )

    return tuple(responsibles.user_identities_from_codeowners(
        flattend_codeowners=flattend_codeowners,
        gh_api=gh_api,
        repo=repo,
    ))


def test_username(gh_api, repo, meta_origin):
    codeowners = '''
    *   @TheLegend27
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert identities.__len__() == 1
    assert identities[0] == responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    )


def test_email(gh_api, repo, meta_origin):
    codeowners = '''
    /.ci   thelegend27@mail.foo
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert identities.__len__() == 1
    assert identities[0] == responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/org/repo',
                email='thelegend27@mail.foo',
            ),
            meta_origin,
        )
    )


def test_username_and_email(gh_api, repo, meta_origin):
    codeowners = '''
    *   @TheLegend27
    /.ci   foo.bar@mail.foo
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert identities.__len__() == 2
    assert identities[0] == responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    )
    assert identities[1] == responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/org/repo',
                email='foo.bar@mail.foo',
            ),
            meta_origin,
        )
    )


def test_username_and_email_same_user(gh_api, repo, meta_origin):
    codeowners = '''
    *   @TheLegend27
    /.ci   thelegend27@mail.foo
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert identities.__len__() == 1
    assert identities[0] == responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    )


def test_teamname(gh_api, repo, meta_origin):
    codeowners = '''
    *   @org/team
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    ) in identities


def test_teamname_and_user(gh_api, repo, meta_origin):
    codeowners = '''
    *   @org/team
    *   @darthvader
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    ) in identities
    assert responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/darthvader',
                username='darthvader',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/darthvader',
                email='darthvader@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/darthvader',
                firstName='Darth',
                lastName='Vader',
            ),
            meta_origin,
        )
    ) in identities


def test_teamname_and_user_and_email_from_team(gh_api, repo, meta_origin):
    codeowners = '''
    *   @org/team
    *   @TheLegend27
    *   thelegend27@mail.foo
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    target = responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    )

    assert identities.count(target) == 1


def test_teamname_and_user_from_team(gh_api, repo, meta_origin):
    codeowners = '''
    *   @org/team
    *   @TheLegend27
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    target = responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    )
    assert identities.count(target) == 1


def test_subteam(gh_api, repo, meta_origin):
    codeowners = '''
    *   @org/subteam
    '''
    identities = user_identities(
        codeowners=codeowners,
        gh_api=gh_api,
        repo=repo,
    )
    assert responsibles.user_model.UserIdentity(
        identifiers=(
            responsibles.user_model.GithubUser(
                source='https://github.foo.bar/thelegend27',
                username='thelegend27',
                github_hostname='github.foo.bar',
            ),
            responsibles.user_model.EmailAddress(
                source='https://github.foo.bar/thelegend27',
                email='thelegend27@mail.foo',
            ),
            responsibles.user_model.PersonalName(
                source='https://github.foo.bar/thelegend27',
                firstName='The Legend',
                lastName='27',
            ),
            meta_origin,
        )
    ) in identities
