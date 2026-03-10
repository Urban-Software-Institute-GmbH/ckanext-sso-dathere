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
    """Log the user into different CKAN versions."""
    log.info("🔐 [CKAN LOGIN] Logging user into CKAN")

    if tk.check_ckan_version(min_version="2.10"):
        login_user(g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
    else:
        user_id = tk.g.user
    set_repoze_user(user_id, resp)

    log.info(u'✅ [CKAN LOGIN] User {0}<{1}> logged in successfully'.format(
        g.user_obj.name, g.user_obj.email))


def sso():
    log.info("🔐 [SSO LOGIN] Redirecting to Keycloak")
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("❌ [SSO LOGIN] Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def sso_register():
    log.info("📝 [SSO REGISTER] Redirecting to Keycloak")
    try:
        auth_url = sso_client.get_authorize_url()
    except Exception as e:
        log.error("❌ [SSO REGISTER] Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)


def dashboard():
    """Callback endpoint after Keycloak authentication."""
    data = tk.request.args

    if 'error' in data:
        log.error(f"❌ [OAUTH ERROR] {data.get('error')} - {data.get('error_description')}")
        h.flash_error('Authentication failed: ' + data.get('error_description', 'Unknown error'))
        return tk.redirect_to(tk.url_for('user.login'))

    # Exchange code for token
    try:
        token_response = sso_client.get_token(data['code'])
    except Exception as e:
        log.error(f"❌ [TOKEN] Error getting token: {e}")
        h.flash_error('Failed to authenticate with SSO provider')
        return tk.redirect_to(tk.url_for('user.login'))

    # Extract client roles and organization roles from token
    client_roles = sso_client.extract_client_roles_from_token(token_response)
    extracted_groups = sso_client.extract_groups_from_token(token_response)
    organization_roles = sso_client.extract_organization_roles_from_groups(extracted_groups)

    # Get userinfo from Keycloak
    try:
        userinfo = sso_client.get_user_info(token_response, user_info_url)
    except Exception as e:
        log.error(f"❌ [USERINFO] Error getting user info: {e}")
        h.flash_error('Failed to get user information')
        return tk.redirect_to(tk.url_for('user.login'))

    log.info(f"👤 [AUTH] User authenticated with client roles: {client_roles}")
    log.debug(f"🧾 [AUTH] Full userinfo: {userinfo}")

    if not userinfo or 'email' not in userinfo:
        log.error("❌ [USERINFO] No userinfo or email returned from Keycloak")
        h.flash_error('Failed to get user information from authentication provider')
        return tk.redirect_to(tk.url_for('user.login'))

    # Determine username
    username = (
        userinfo.get('given_name') or
        userinfo.get('nickname') or
        userinfo.get('preferred_username') or
        userinfo['email'].split('@')[0]
    )

    if not username:
        log.error("❌ [USERINFO] No username could be determined from userinfo")
        h.flash_error('Could not determine username from SSO provider')
        return tk.redirect_to(tk.url_for('user.login'))

    # Prepare user dictionary for CKAN
    user_dict = {
        'name': helpers.ensure_unique_username(username),
        'email': userinfo['email'],
        'password': helpers.generate_password(),
        'fullname': userinfo.get('name', ''),
        'plugin_extras': {
            'idp': userinfo.get('sub', ''),
            'idp_provider': 'keycloak',
            'client_roles': client_roles,
            'keycloak_groups': extracted_groups,
            'organization_roles': organization_roles
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
        log.error(f"❌ [USER PROCESS] Error processing user: {e}")
        h.flash_error('Error creating/updating user')
        return tk.redirect_to(tk.url_for('user.login'))

    # Sync CKAN organization memberships from Keycloak groups
    try:
        helpers.sync_user_organizations(g.user_obj, organization_roles)
    except Exception as e:
        # Never crash login because of org sync
        log.error(f"❌ [ORG SYNC] Unexpected error syncing organizations for user {g.user_obj.name}: {e}")

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
        log.error(f"❌ [CKAN LOGIN] Error logging user into CKAN: {e}")
        h.flash_error('Error completing login')
        return tk.redirect_to(tk.url_for('user.login'))

    log.info(
        f"✅ [LOGIN SUCCESS] User {g.user_obj.name} logged in successfully "
        f"with client roles: {client_roles} and org roles: {organization_roles}"
    )
    h.flash_success('Logged in successfully')

    return response


def sso_logout():
    """Logout from both CKAN and Keycloak."""
    log.info("🚪 [LOGOUT] Logging out user from CKAN and Keycloak")

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

    # Redirect to Keycloak logout
    logout_url = tk.config.get('ckanext.sso.logout_url')
    if logout_url:
        try:
            logout_url_full = sso_client.get_logout_url(return_to=came_from)
            if logout_url_full:
                log.info("🚪 [LOGOUT] Redirecting to Keycloak logout")
                return tk.redirect_to(logout_url_full)
        except Exception as e:
            log.error(f"❌ [LOGOUT] Error during Keycloak logout redirect: {e}")

    return tk.redirect_to('/')


def reset_password():
    """Override password reset to prevent SSO users from resetting."""
    email = tk.request.form.get('user', None)

    if '@' not in email:
        log.info(f'⚠️ [RESET PASSWORD] Invalid email: {email}')
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.request_reset'))

    user_list = model.User.by_email(email)
    if not user_list:
        log.info(f'⚠️ [RESET PASSWORD] Unknown user: {email}')
        return tk.redirect_to(tk.url_for('user.login'))

    user = user_list[0] if isinstance(user_list, list) else user_list

    # Check if user is from SSO
    if user.plugin_extras and user.plugin_extras.get('idp_provider') == 'keycloak':
        log.info(f'🔒 [RESET PASSWORD] SSO user {user.name} attempted password reset')
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