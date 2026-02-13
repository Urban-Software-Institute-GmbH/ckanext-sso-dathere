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
    
    # Check for admin role in client roles and promote if needed
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
    Check if user has admin role in Keycloak client roles 
    and promote to CKAN sysadmin.
    '''
    plugin_extras = user_dict.get('plugin_extras', {})
    
    # Get ONLY client roles
    client_roles = plugin_extras.get('client_roles', [])
    
    # Define what constitutes an "admin" role in your client
    # These are the client role names you want to map to CKAN sysadmin
    admin_roles = ['admin', 'administrator', 'sysadmin', 'ckan_admin', 'ckan-admin']
    
    has_admin_role = False
    
    # Check if any of the user's client roles match admin roles
    for role in client_roles:
        if role.lower() in [r.lower() for r in admin_roles]:
            has_admin_role = True
            log.info(f"User {user.name} has admin client role '{role}'")
            break
    
    # Promote or demote based on client role
    if has_admin_role and not user.sysadmin:
        # User has admin client role but is not sysadmin - promote
        _set_sysadmin(user, True)
        log.info(f"User {user.name} promoted to sysadmin based on client role")
    elif not has_admin_role and user.sysadmin:
        # User lost admin client role - demote
        _set_sysadmin(user, False)
        log.info(f"User {user.name} demoted from sysadmin - no longer has admin client role")
    elif has_admin_role and user.sysadmin:
        log.debug(f"User {user.name} already has sysadmin privileges")
    else:
        log.debug(f"User {user.name} does not have admin client role")


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


def user_has_client_role(user, role_name):
    '''
    Helper to check if a user has a specific client role.
    Useful for templates and other extensions.
    
    Args:
        user: CKAN user object
        role_name: The client role name to check for
        
    Returns:
        bool: True if user has the role
    '''
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return False
    
    client_roles = user.plugin_extras.get('client_roles', [])
    return role_name in client_roles


def get_user_client_roles(user):
    '''
    Get all client roles for a user.
    
    Args:
        user: CKAN user object
        
    Returns:
        list: List of client role names
    '''
    if not user or not hasattr(user, 'plugin_extras') or not user.plugin_extras:
        return []
    
    return user.plugin_extras.get('client_roles', [])