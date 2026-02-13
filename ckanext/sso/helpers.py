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
    '''Generate a random password.'''
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(8))


def ensure_unique_username(given_name):
    '''Ensure that the username is unique.'''
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
    '''Process user info from SSO provider and create/update user in CKAN.'''
    user = _get_user_by_email(user_dict.get('email'))
    
    if user:
        # Update existing user
        user = _update_user(user, user_dict)
    else:
        # Create new user
        user = _create_user(user_dict)
    
    # Check for admin role and promote if needed
    _check_and_promote_to_admin(user, user_dict)
    
    return user


def _get_user_by_email(email):
    user = model.User.by_email(email)
    if user and isinstance(user, list):
        user = user[0]

    activate_user_if_deleted(user)
    return user


def activate_user_if_deleted(user):
    '''Reactivates deleted user.'''
    if not user:
        return
    if user.is_deleted():
        user.activate()
        user.commit()
        log.info(u'User {} reactivated'.format(user.name))


def _create_user(user_dict):
    '''Create a new user.'''
    context = {u'ignore_auth': True}
    
    # Prepare user dict for CKAN
    ckan_user_dict = {
        'name': user_dict['name'],
        'email': user_dict['email'],
        'password': user_dict['password'],
        'fullname': user_dict.get('fullname', ''),
    }
    
    # Add image if present
    if user_dict.get('image_url'):
        ckan_user_dict['image_url'] = user_dict['image_url']
    
    # Add plugin_extras if present
    if user_dict.get('plugin_extras'):
        ckan_user_dict['plugin_extras'] = user_dict['plugin_extras']
    
    created_user_dict = tk.get_action(u'user_create')(context, ckan_user_dict)
    return _get_user_by_email(created_user_dict['email'])


def _update_user(user, user_dict):
    '''Update existing user with new information from SSO.'''
    context = {u'ignore_auth': True}
    
    update_dict = {
        'id': user.id,
        'name': user.name,
        'fullname': user_dict.get('fullname', user.fullname or ''),
        'email': user_dict.get('email', user.email),
    }
    
    # Update plugin_extras if provided
    if user_dict.get('plugin_extras'):
        # Merge with existing plugin_extras
        existing_extras = user.plugin_extras or {}
        existing_extras.update(user_dict['plugin_extras'])
        update_dict['plugin_extras'] = existing_extras
    
    tk.get_action(u'user_update')(context, update_dict)
    return model.User.get(user.id)


def _check_and_promote_to_admin(user, user_dict):
    '''
    Check if user has admin role in Keycloak and promote to CKAN sysadmin.
    '''
    plugin_extras = user_dict.get('plugin_extras', {})
    roles = plugin_extras.get('roles', {})
    
    # Check for admin role in realm roles
    realm_roles = roles.get('realm', [])
    # Check for admin role in client roles
    client_roles = roles.get('client', [])
    
    # Define what constitutes an "admin" role
    # You can customize this list based on your Keycloak role names
    admin_roles = ['admin', 'administrator', 'sysadmin', 'ckan_admin']
    
    has_admin_role = False
    
    # Check realm roles
    for role in realm_roles:
        if role.lower() in admin_roles:
            has_admin_role = True
            log.info(f"User {user.name} has admin role '{role}' in realm")
            break
    
    # Check client roles if not already found
    if not has_admin_role:
        for role in client_roles:
            if role.lower() in admin_roles:
                has_admin_role = True
                log.info(f"User {user.name} has admin role '{role}' in client")
                break
    
    # Promote or demote based on role
    if has_admin_role and not user.sysadmin:
        # User has admin role but is not sysadmin - promote
        _set_sysadmin(user, True)
        log.info(f"User {user.name} promoted to sysadmin based on Keycloak role")
    elif not has_admin_role and user.sysadmin:
        # User lost admin role - demote
        _set_sysadmin(user, False)
        log.info(f"User {user.name} demoted from sysadmin - no longer has admin role")
    elif has_admin_role and user.sysadmin:
        log.debug(f"User {user.name} already has sysadmin privileges")
    else:
        log.debug(f"User {user.name} does not have admin role")


def _set_sysadmin(user, is_admin):
    '''Set or unset user as sysadmin.'''
    try:
        # Use CKAN's internal method to set sysadmin
        user.sysadmin = is_admin
        user.save()
        model.Session.commit()
        log.info(f"Set sysadmin={is_admin} for user {user.name}")
    except Exception as e:
        log.error(f"Error setting sysadmin for user {user.name}: {e}")
        model.Session.rollback()


def check_default_login():
    '''Check if default login is enabled.'''
    return tk.asbool(tk.config.get('ckanext.sso.disable_ckan_login', False))


def user_has_role(user, role_name, role_type='realm'):
    '''
    Helper to check if a user has a specific role.
    Useful for templates and other extensions.
    '''
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return False
    
    roles = user.plugin_extras.get('roles', {})
    
    if role_type == 'realm':
        return role_name in roles.get('realm', [])
    elif role_type == 'client':
        return role_name in roles.get('client', [])
    else:
        # Check all roles
        all_roles = roles.get('realm', []) + roles.get('client', [])
        return role_name in all_roles


def get_user_roles(user):
    '''
    Get all roles for a user.
    '''
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return {'realm': [], 'client': []}
    
    return user.plugin_extras.get('roles', {'realm': [], 'client': []})