'''
Contains key constants to access variables embedded in the applications' or requests' context. Both
are dict-like objects, so the constants can be used to retrieve the desired variables like they were
globally available.
'''

APP_ADDRESSBOOK_ENTRIES = 'addressbook_entries'
APP_ADDRESSBOOK_GITHUB_MAPPINGS = 'addressbook_github_mappings'
APP_ADDRESSBOOK_SOURCE = 'addressbook_source'
APP_BASE_URL = 'base_url'
APP_COMPONENT_DESCRIPTOR_LOOKUP = 'component_descriptor_lookup'
APP_COMPONENT_WITH_TESTS_CALLBACK = 'component_with_tests_callback'
APP_EOL_CLIENT = 'eol_client'
APP_EXTENSIONS_CFG = 'extensions_cfg'
APP_FINDING_CFGS = 'finding_cfgs'
APP_GITHUB_API_LOOKUP = 'github_api_lookup'
APP_GITHUB_REPO_LOOKUP = 'github_repo_lookup'
APP_KUBERNETES_API_CALLBACK = 'kubernetes_api_callback'
APP_NAMESPACE_CALLBACK = 'namespace_callback'
APP_OCI_CLIENT = 'oci_client'
APP_PROFILES_CALLBACK = 'profiles_callback'
APP_SECRET_FACTORY = 'secret_factory'
APP_SPECIAL_COMPONENT_CALLBACK = 'special_component_callback'
APP_SPRINTS = 'sprints'
APP_SPRINTS_METADATA = 'sprints_metadata'

# `db_session` is intended to be used for tasks which have to be finished in a timely manner
REQUEST_DB_SESSION = 'db_session'
# `db_session_low_prio` has a small connection pool with a long timeout for low prio tasks
REQUEST_DB_SESSION_LOW_PRIO = 'db_session_low_prio'
REQUEST_USER_ID = 'user_id'
REQUEST_USER_ROLES = 'user_roles'

BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS = 60
RESCORING_OPERATOR_SET_TO_PREFIX = 'set-to-'
