# -*- coding: utf-8 -*-
import logging
import string
import re
import random
import secrets

import ckan.model as model
import ckan.plugins.toolkit as tk

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
        random_number = int(random.SystemRandom().random() * 10000)
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


def _get_user_organization_memberships(user):
    """
    Fetch all current CKAN organization memberships for the user.

    Returns:
        dict: {org_name: capacity}
    """
    memberships = {}

    try:
        context = {'ignore_auth': True}
        data_dict = {'id': user.name}

        user_data = tk.get_action('user_show')(context, data_dict)

        for org in user_data.get('organizations', []):
            org_name = org.get('name')
            capacity = org.get('capacity')
            if org_name and capacity:
                memberships[org_name] = capacity

        log.info(f"📋 [ORG CURRENT] Current CKAN org memberships for '{user.name}': {memberships}")

    except Exception as e:
        log.error(f"❌ [ORG CURRENT] Failed to fetch current organizations for '{user.name}': {e}")

    return memberships


def _remove_user_from_organization(user, org_name):
    """
    Remove a user from a CKAN organization.
    """
    try:
        context = {
            'ignore_auth': True,
            'user': user.name,
            'auth_user_obj': user
        }

        data_dict = {
            'id': org_name,
            'object': user.name,
            'object_type': 'user'
        }

        tk.get_action('member_delete')(context, data_dict)

        log.info(f"🗑️ [ORG REMOVE] Removed user '{user.name}' from organization '{org_name}'")

    except Exception as e:
        log.error(
            f"❌ [ORG REMOVE] Failed to remove user '{user.name}' from organization '{org_name}': {e}"
        )


def _add_user_to_organization(user, org_name, capacity):
    """
    Add a user to a CKAN organization with the given role.
    """
    try:
        context = {
            'ignore_auth': True,
            'user': user.name,
            'auth_user_obj': user
        }

        data_dict = {
            'id': org_name,
            'object': user.name,
            'object_type': 'user',
            'capacity': capacity
        }

        tk.get_action('member_create')(context, data_dict)

        log.info(
            f"✅ [ORG ADD] Added user '{user.name}' as '{capacity}' in organization '{org_name}'"
        )

    except Exception as e:
        log.error(
            f"❌ [ORG ADD] Failed to add user '{user.name}' "
            f"to organization '{org_name}' with role '{capacity}': {e}"
        )


def sync_user_organizations(user, organization_roles):
    """
    Sync all CKAN organization memberships from Keycloak.

    Keycloak is the single source of truth.

    Args:
        user: CKAN user object
        organization_roles: dict like
            {
                "ui": "admin",
                "mobility": "editor",
                "public-data": "member"
            }

    Behavior:
    - If user is in CKAN org but not in Keycloak anymore -> remove
    - If user role changed -> remove old and add new
    - If user is missing in CKAN but present in Keycloak -> add
    - If org does not exist in CKAN -> skip without crashing
    """
    if not user:
        log.warning("⚠️ [ORG SYNC] No user provided, skipping organization sync")
        return

    if organization_roles is None:
        organization_roles = {}

    if not isinstance(organization_roles, dict):
        log.warning(
            f"⚠️ [ORG SYNC] organization_roles is not a dict for user '{user.name}': {organization_roles}"
        )
        return

    allowed_roles = {'admin', 'editor', 'member'}

    desired_roles = {
        org_name: role
        for org_name, role in organization_roles.items()
        if isinstance(org_name, str) and role in allowed_roles
    }

    current_roles = _get_user_organization_memberships(user)

    log.info(f"📋 [ORG SYNC] Desired Keycloak roles for '{user.name}': {desired_roles}")

    all_orgs = set(current_roles.keys()) | set(desired_roles.keys())

    for org_name in all_orgs:
        try:
            current_role = current_roles.get(org_name)
            desired_role = desired_roles.get(org_name)

            # User currently in CKAN org, but no longer in Keycloak -> remove
            if current_role and not desired_role:
                log.info(
                    f"🧹 [ORG SYNC] Removing user '{user.name}' from '{org_name}' "
                    f"because it is no longer present in Keycloak"
                )
                _remove_user_from_organization(user, org_name)
                continue

            # User not in CKAN org, but should be -> add
            if not current_role and desired_role:
                if not _organization_exists(org_name):
                    log.warning(
                        f"⚠️ [ORG SYNC] Cannot add user '{user.name}' to missing organization '{org_name}'"
                    )
                    continue

                log.info(
                    f"➕ [ORG SYNC] Adding user '{user.name}' to '{org_name}' as '{desired_role}'"
                )
                _add_user_to_organization(user, org_name, desired_role)
                continue

            # User in CKAN org and in Keycloak, but role changed -> replace
            if current_role and desired_role and current_role != desired_role:
                if not _organization_exists(org_name):
                    log.warning(
                        f"⚠️ [ORG SYNC] Cannot update user '{user.name}' in missing organization '{org_name}'"
                    )
                    continue

                log.info(
                    f"🔄 [ORG SYNC] Changing user '{user.name}' in '{org_name}' "
                    f"from '{current_role}' to '{desired_role}'"
                )
                _remove_user_from_organization(user, org_name)
                _add_user_to_organization(user, org_name, desired_role)
                continue

            # Same role -> nothing to do
            if current_role and desired_role and current_role == desired_role:
                log.info(
                    f"✅ [ORG SYNC] User '{user.name}' already has correct role "
                    f"'{desired_role}' in '{org_name}'"
                )
                continue

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