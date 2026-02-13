# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import logging
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk

import ckanext.sso.helpers as helpers
from ckanext.sso.views import get_blueprint


log = logging.getLogger(__name__)


class SSOPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # ITemplateHelpers

    def get_helpers(self):
        return {
            'check_default_login': helpers.check_default_login,
            'user_has_client_role': helpers.user_has_client_role,
            'get_user_client_roles': helpers.get_user_client_roles,
        }

    # IConfigurer

    def update_config(self, config_):
        tk.add_template_directory(config_, 'templates')
        tk.add_public_directory(config_, 'public')
        tk.add_resource('assets', 'sso')

    def get_blueprint(self):
        return get_blueprint()
    
    # IAuthenticator
    
    def identify(self):
        """Identify the user - handled by the blueprint"""
        pass
    
    def logout(self):
        """Handle logout - we'll let the blueprint handle it"""
        return None
    
    def login(self):
        """Handle login - we'll let the blueprint handle it"""
        return None