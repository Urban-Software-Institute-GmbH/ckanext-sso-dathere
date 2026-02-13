# encoding: utf-8

import logging
import jwt
from jwt.exceptions import PyJWTError
from requests_oauthlib import OAuth2Session
from ckan.plugins import toolkit as tk
from urllib.parse import urlencode

log = logging.getLogger(__name__)


class SSOClient(object):
    def __init__(self, client_id, client_secret, authorize_url, token_url,
                 redirect_url, user_info_url, scope, logout_url=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.redirect_url = redirect_url
        self.user_info_url = user_info_url
        self.scope = scope
        self.logout_url = logout_url

    def get_authorize_url(self, **kwargs):
        log.debug('get_authorize_url')
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_url,
                            scope=self.scope)
        authorization_url, state = oauth.authorization_url(self.authorize_url, **kwargs)
        return authorization_url

    def get_logout_url(self, return_to=None):
        """Get Keycloak logout URL"""
        params = {}
        if return_to:
            params['post_logout_redirect_uri'] = return_to
        if params:
            return f"{self.logout_url}?{urlencode(params)}"
        return self.logout_url

    def get_token(self, code):
        log.debug('get_token')
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_url,
                              scope=self.scope)
        token = oauth.fetch_token(self.token_url, code=code,
                                  client_secret=self.client_secret)
        return token

    def get_user_info(self, token, user_info_url):
        log.debug('get_user_info')
        oauth = OAuth2Session(self.client_id, token=token)
        user_info = oauth.get(user_info_url)
        return user_info.json()
    
    def extract_roles_from_token(self, token_response):
        """
        Extract roles from the access_token JWT.
        
        Args:
            token_response: The full token response from get_token()
            
        Returns:
            dict: Contains realm_roles and client_roles
        """
        result = {
            'realm_roles': [],
            'client_roles': []
        }
        
        access_token = token_response.get('access_token')
        if not access_token:
            log.warning("No access_token in token response")
            return result
        
        try:
            # Decode without verification for development
            # WARNING: For production, you should verify the signature!
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            
            # Extract realm roles
            realm_access = decoded.get('realm_access', {})
            result['realm_roles'] = realm_access.get('roles', [])
            
            # Extract client roles for your specific client
            resource_access = decoded.get('resource_access', {})
            if self.client_id in resource_access:
                result['client_roles'] = resource_access[self.client_id].get('roles', [])
            
            # Also store all client roles for reference
            result['all_client_roles'] = {}
            for client_name, client_data in resource_access.items():
                result['all_client_roles'][client_name] = client_data.get('roles', [])
            
            log.debug(f"Extracted realm roles: {result['realm_roles']}")
            log.debug(f"Extracted client roles: {result['client_roles']}")
            
        except PyJWTError as e:
            log.error(f"Error decoding JWT: {e}")
        
        return result
    
    def extract_roles_from_userinfo(self, user_info):
        """
        Extract roles from userinfo response if Keycloak is configured to include them.
        """
        result = {
            'realm_roles': [],
            'client_roles': []
        }
        
        # Check common places where roles might appear in userinfo
        if 'realm_access' in user_info:
            result['realm_roles'] = user_info['realm_access'].get('roles', [])
        
        if 'resource_access' in user_info:
            resource_access = user_info['resource_access']
            if self.client_id in resource_access:
                result['client_roles'] = resource_access[self.client_id].get('roles', [])
        
        # Some Keycloak versions put roles directly in 'roles' field
        if 'roles' in user_info:
            result['realm_roles'] = user_info['roles']
        
        return result