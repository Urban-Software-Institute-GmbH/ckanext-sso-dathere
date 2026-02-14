# encoding: utf-8

import logging

from flask import Blueprint

import ckan.lib.helpers as h
import ckan.model as model
from ckan.plugins import toolkit as tk
import ckan.plugins as plugins
from ckan.views.user import set_repoze_user, RequestResetView
from ckan.common import (
    _, config, g, request, current_user, logout_user, session, login_user
)


from ckanext.sso.ssoclient import SSOClient
import ckanext.sso.helpers as helpers

log = logging.getLogger(__name__)

blueprint = Blueprint('sso', __name__)


# Load configuration
authorization_endpoint = tk.config.get('ckanext.sso.authorization_endpoint')
login_url = tk.config.get('ckanext.sso.login_url')
client_id = tk.config.get('ckanext.sso.client_id')
redirect_url = tk.config.get('ckanext.sso.redirect_url')
client_secret = tk.config.get('ckanext.sso.client_secret')
response_type = tk.config.get('ckanext.sso.response_type')
scope = tk.config.get('ckanext.sso.scope')
access_token_url = tk.config.get('ckanext.sso.access_token_url')
user_info_url = tk.config.get('ckanext.sso.user_info')
logout_url = tk.config.get('ckanext.sso.logout_url') 


# Initialize SSO client
sso_client = SSOClient(
    client_id=client_id, 
    client_secret=client_secret,
    authorize_url=authorization_endpoint,
    token_url=access_token_url,
    redirect_url=redirect_url,
    user_info_url=user_info_url,
    scope=scope,
    logout_url=logout_url
)


@blueprint.before_app_request
def before_app_request():
    bp, action = tk.get_endpoint()
    if bp == 'user' and action == 'login' and helpers.check_default_login():
        return tk.redirect_to(h.url_for('sso.sso'))
    if bp == 'user' and action == 'register':
        return tk.redirect_to(h.url_for('sso.sso_register'))
    if bp == 'user' and action == 'logout':
        return tk.redirect_to(h.url_for('sso.sso_logout'))
    

def _log_user_into_ckan(resp):
    """ Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    log.info("Logging user into CKAN")
    
    if tk.check_ckan_version(min_version="2.10"):
        login_user(g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
    else:
        user_id = tk.g.user
    set_repoze_user(user_id, resp)

    log.info(u'User {0}<{1}> logged in successfully'.format(
        g.user_obj.name, g.user_obj.email))


def sso():
    log.info("SSO Login - Redirecting to Keycloak")
    auth_url = None
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def sso_register():
    log.info("SSO Register - Redirecting to Keycloak")
    auth_url = None
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def dashboard():
    """Callback endpoint after Keycloak authentication."""
    data = tk.request.args
    
    if 'error' in data:
        log.error(f"OAuth error: {data.get('error')} - {data.get('error_description')}")
        h.flash_error('Authentication failed: ' + data.get('error_description', 'Unknown error'))
        return tk.redirect_to(tk.url_for('user.login'))  # ← Make sure to return!
    
    # Exchange code for token
    try:
        token_response = sso_client.get_token(data['code'])
    except Exception as e:
        log.error(f"Error getting token: {e}")
        h.flash_error('Failed to authenticate with SSO provider')
        return tk.redirect_to(tk.url_for('user.login'))  # ← Return on error
    
    # Extract ONLY client roles from the access token
    client_roles = sso_client.extract_client_roles_from_token(token_response)
    
    # Get userinfo from Keycloak
    try:
        userinfo = sso_client.get_user_info(token_response, user_info_url)
    except Exception as e:
        log.error(f"Error getting user info: {e}")
        h.flash_error('Failed to get user information')
        return tk.redirect_to(tk.url_for('user.login'))  # ← Return on error
    
    log.info(f"User authenticated with client roles: {client_roles}")
    log.debug(f"Full userinfo: {userinfo}")
    
    if not userinfo or 'email' not in userinfo:
        log.error("No userinfo or email returned from Keycloak")
        h.flash_error('Failed to get user information from authentication provider')
        return tk.redirect_to(tk.url_for('user.login'))  # ← Return on error
    
    # Determine username
    username = (
        userinfo.get('given_name') or 
        userinfo.get('nickname') or 
        userinfo.get('preferred_username') or
        userinfo['email'].split('@')[0]
    )
    
    if not username:
        log.error("No username could be determined from userinfo")
        h.flash_error('Could not determine username from SSO provider')
        return tk.redirect_to(tk.url_for('user.login'))  # ← Return on error
    
    # Prepare user dictionary for CKAN - ONLY storing client roles
    user_dict = {
        'name': helpers.ensure_unique_username(username),
        'email': userinfo['email'],
        'password': helpers.generate_password(),
        'fullname': userinfo.get('name', ''),
        'plugin_extras': {
            'idp': userinfo.get('sub', ''),
            'idp_provider': 'keycloak',
            'client_roles': client_roles  # Store ONLY client roles
        }
    }

    # Add picture if available
    picture_url = (
        userinfo.get('picture') or 
        userinfo.get('avatar') or 
        userinfo.get('image')
    )
    if picture_url:
        user_dict['image_url'] = picture_url
    
    # Process user (create or update)
    try:
        g.user_obj = helpers.process_user(user_dict)
        g.user = g.user_obj.name
    except Exception as e:
        log.error(f"Error processing user: {e}")
        h.flash_error('Error creating/updating user')
        return tk.redirect_to(tk.url_for('user.login'))  # ← Return on error
    
    # Set context for CKAN
    context = {
        "model": model, 
        "session": model.Session,
        'user': g.user,
        'auth_user_obj': g.user_obj
    }

    # Log user into CKAN
    try:
        response = tk.redirect_to(tk.url_for('user.me', context))
        _log_user_into_ckan(response)
    except Exception as e:
        log.error(f"Error logging user into CKAN: {e}")
        h.flash_error('Error completing login')
        return tk.redirect_to(tk.url_for('user.login'))  # ← Return on error
    
    # Success message based on admin status
    if g.user_obj.sysadmin:
        h.flash_success(f'Logged in as administrator')
        log.info(f"Admin user {g.user_obj.name} logged in successfully with roles: {client_roles}")
    else:
        log.info(f"Regular user {g.user_obj.name} logged in successfully with roles: {client_roles}")
        h.flash_success(f'Logged in successfully')
    
    return response  # ← Make sure this is always returned!


def sso_logout():
    """Logout from both CKAN and Keycloak."""
    log.info("Logging out user from CKAN and Keycloak")
    
    # Call IAuthenticator plugins
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        response = item.logout()
        if response:
            return response
    
    user = current_user.name if hasattr(current_user, 'name') else None
    
    # Get the redirect URL before clearing session
    came_from = request.args.get('came_from', '/')
    
    # Clear CKAN session
    logout_user()
    
    # Remove CSRF token
    field_name = config.get("WTF_CSRF_FIELD_NAME")
    if session.get(field_name):
        session.pop(field_name)
    
    # Clear the entire session to be safe
    session.clear()
    
    # IMPORTANT: Redirect to Keycloak logout
    logout_url = tk.config.get('ckanext.sso.logout_url')
    if logout_url:
        try:
            # Redirect to Keycloak logout, which will then redirect back to home
            logout_url_full = sso_client.get_logout_url(return_to=came_from)
            if logout_url_full:
                log.info(f"Redirecting to Keycloak logout")
                return tk.redirect_to(logout_url_full)
        except Exception as e:
            log.error(f"Error during Keycloak logout redirect: {e}")
    
    # Fallback to home page
    return tk.redirect_to('/')


def reset_password():
    """Override password reset to prevent SSO users from resetting."""
    email = tk.request.form.get('user', None)
    
    if '@' not in email:
        log.info(f'User requested reset link for invalid email: {email}')
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.request_reset'))
    
    user_list = model.User.by_email(email)
    if not user_list:
        log.info(f'User requested reset link for unknown user: {email}')
        return tk.redirect_to(tk.url_for('user.login'))
    
    user = user_list[0] if isinstance(user_list, list) else user_list
    
    # Check if user is from SSO
    if user.plugin_extras and user.plugin_extras.get('idp_provider') == 'keycloak':
        log.info(f'SSO user {user.name} attempted password reset')
        h.flash_error('Password reset is not available for SSO users. Please use your identity provider.')
        return tk.redirect_to(tk.url_for('user.login'))
    
    return RequestResetView().post()


# Register routes
blueprint.add_url_rule('/sso', view_func=sso)
blueprint.add_url_rule('/sso_register', view_func=sso_register)
blueprint.add_url_rule('/dashboard', view_func=dashboard)
blueprint.add_url_rule('/sso_logout', view_func=sso_logout)
blueprint.add_url_rule('/reset_password', view_func=reset_password, methods=['POST'])


def get_blueprint():
    return blueprint