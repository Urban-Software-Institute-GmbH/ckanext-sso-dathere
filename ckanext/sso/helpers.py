# -*- coding: utf-8 -*-
import logging
import string
import re
import random
import secrets

import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan.model import User

log = logging.getLogger(__name__)


def generate_password():
    """Generate a random password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(8))


def ensure_unique_username(given_name):
    """Ensure that the username is unique."""
    cleaned_localpart = re.sub(r'[^\w]', '-', given_name).lower()

    if not model.User.get(cleaned_localpart):
        return cleaned_localpart

    max_name_creation_attempts = 10

    for _ in range(max_name_creation_attempts):
        random_number = random.SystemRandom().random() * 10000
        name = '%s-%d' % (cleaned_localpart, random_number)
        if not model.User.get(name):
            return name

    return cleaned_localpart


def process_user(user_dict):
    """
    Process user info from SSO provider and create/update user in CKAN.

    Note:
    This function does NOT promote users to CKAN sysadmin.
    Organization-level roles are handled separately via Keycloak groups.
    """
    user = _get_user_by_email(user_dict.get('email'))

    if user:
        user = _update_user(user, user_dict)
    else:
        user = _create_user(user_dict)

    return user


def _get_user_by_email(email):
    user = model.User.by_email(email)
    if user and isinstance(user, list):
        user = user[0]

    activate_user_if_deleted(user)
    return user


def activate_user_if_deleted(user):
    """Reactivates deleted user."""
    if not user:
        return
    if user.is_deleted():
        user.activate()
        user.commit()
        log.info(u'✅ [USER] User {} reactivated'.format(user.name))


def _create_user(user_dict):
    """Create a new user."""
    context = {u'ignore_auth': True}

    ckan_user_dict = {
        'name': user_dict['name'],
        'email': user_dict['email'],
        'password': user_dict['password'],
        'fullname': user_dict.get('fullname', ''),
    }

    if user_dict.get('image_url'):
        ckan_user_dict['image_url'] = user_dict['image_url']

    if user_dict.get('plugin_extras'):
        ckan_user_dict['plugin_extras'] = user_dict['plugin_extras']

    created_user_dict = tk.get_action(u'user_create')(context, ckan_user_dict)
    log.info(f"✅ [USER CREATE] Created CKAN user {created_user_dict['name']}")
    return _get_user_by_email(created_user_dict['email'])


def _update_user(user, user_dict):
    """Update existing user with new information from SSO."""
    context = {u'ignore_auth': True}

    update_dict = {
        'id': user.id,
        'name': user.name,
        'fullname': user_dict.get('fullname', user.fullname or ''),
        'email': user_dict.get('email', user.email),
    }

    if user_dict.get('plugin_extras'):
        existing_extras = user.plugin_extras or {}
        existing_extras.update(user_dict['plugin_extras'])
        update_dict['plugin_extras'] = existing_extras

    tk.get_action(u'user_update')(context, update_dict)
    log.info(f"🔄 [USER UPDATE] Updated CKAN user {user.name}")
    return model.User.get(user.id)


def _organization_exists(org_name):
    """
    Check whether a CKAN organization exists.

    Returns:
        bool
    """
    try:
        tk.get_action('organization_show')(
            {'ignore_auth': True},
            {'id': org_name}
        )
        return True
    except Exception as e:
        log.warning(f"⚠️ [ORG CHECK] Organization '{org_name}' does not exist or cannot be accessed: {e}")
        return False


def _add_or_update_user_organization_role(user, org_name, capacity):
    """
    Add or update a user's membership in a CKAN organization.

    capacity should be one of:
        admin, editor, member

    This function never raises an exception outward.
    """
    try:
        context = {
            'ignore_auth': True,
            'user': user.name,
            'auth_user_obj': user
        }

        data_dict = {
            'id': org_name,
            'username': user.name,
            'role': capacity
        }

        tk.get_action('member_create')(context, data_dict)

        log.info(
            f"✅ [ORG SYNC] Ensured user '{user.name}' is '{capacity}' in organization '{org_name}'"
        )

    except Exception as e:
        log.error(
            f"❌ [ORG SYNC] Failed to add/update user '{user.name}' "
            f"in organization '{org_name}' with role '{capacity}': {e}"
        )


def sync_user_organizations(user, organization_roles):
    """
    Sync user organization memberships from resolved Keycloak organization roles.

    Args:
        user: CKAN user object
        organization_roles: dict like
            {
                "org-a": "admin",
                "org-b": "editor",
                "org-c": "member"
            }

    Behavior:
    - Invalid input is ignored safely
    - Missing organizations do not crash the app
    - Unknown roles are ignored
    - Only adds/updates memberships for organizations present in organization_roles
    - Does NOT remove memberships from other organizations
    """
    if not user:
        log.warning("⚠️ [ORG SYNC] No user provided, skipping organization sync")
        return

    if not organization_roles:
        log.info(f"ℹ️ [ORG SYNC] No organization roles to sync for user '{user.name}'")
        return

    if not isinstance(organization_roles, dict):
        log.warning(
            f"⚠️ [ORG SYNC] organization_roles is not a dict for user '{user.name}': {organization_roles}"
        )
        return

    allowed_roles = {'admin', 'editor', 'member'}

    for org_name, capacity in organization_roles.items():
        try:
            if not org_name or not isinstance(org_name, str):
                log.warning(f"⚠️ [ORG SYNC] Invalid organization name ignored: {org_name}")
                continue

            if capacity not in allowed_roles:
                log.warning(
                    f"⚠️ [ORG SYNC] Invalid capacity '{capacity}' for organization '{org_name}', skipping"
                )
                continue

            if not _organization_exists(org_name):
                log.warning(
                    f"⚠️ [ORG SYNC] Skipping membership sync because organization '{org_name}' does not exist"
                )
                continue

            _add_or_update_user_organization_role(user, org_name, capacity)

        except Exception as e:
            log.error(
                f"❌ [ORG SYNC] Unexpected error while syncing organization '{org_name}' "
                f"for user '{user.name}': {e}"
            )
            continue


def check_default_login():
    """Check if default login is enabled."""
    return tk.asbool(tk.config.get('ckanext.sso.disable_ckan_login', False))


def user_has_client_role(user, role_name):
    """
    Helper to check if a user has a specific client role.
    Useful for templates and other extensions.
    """
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return False

    client_roles = user.plugin_extras.get('client_roles', [])
    return role_name in client_roles


def get_user_client_roles(user):
    """
    Get all client roles for a user.
    """
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return []

    return user.plugin_extras.get('client_roles', [])


def get_user_organization_roles(user):
    """
    Get resolved organization roles stored in plugin_extras.

    Returns:
        dict
    """
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return {}

    return user.plugin_extras.get('organization_roles', {})