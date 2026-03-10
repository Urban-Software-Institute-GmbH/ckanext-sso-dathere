# encoding: utf-8

import logging
import jwt
from jwt.exceptions import PyJWTError
from requests_oauthlib import OAuth2Session
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
        log.debug("🔐 [SSO] Building authorize URL")
        oauth = OAuth2Session(
            self.client_id,
            redirect_uri=self.redirect_url,
            scope=self.scope
        )
        kwargs["prompt"] = "login"
        authorization_url, state = oauth.authorization_url(self.authorize_url, **kwargs)
        return authorization_url

    def get_logout_url(self, return_to=None):
        """
        Get Keycloak logout URL.

        Args:
            return_to: URL to redirect back to after logout (optional)

        Returns:
            str: Logout URL or None if logout_url not configured
        """
        if not self.logout_url:
            log.debug("ℹ️ [SSO LOGOUT] logout_url not configured for SSOClient")
            return None

        params = {}
        if return_to:
            params["post_logout_redirect_uri"] = return_to

        if params:
            return f"{self.logout_url}?{urlencode(params)}"

        return self.logout_url

    def get_token(self, code):
        log.debug("🔐 [SSO] Fetching token")
        oauth = OAuth2Session(
            self.client_id,
            redirect_uri=self.redirect_url,
            scope=self.scope
        )
        token = oauth.fetch_token(
            self.token_url,
            code=code,
            client_secret=self.client_secret
        )
        return token

    def get_user_info(self, token, user_info_url):
        log.debug("👤 [SSO] Fetching user info")
        oauth = OAuth2Session(self.client_id, token=token)
        user_info = oauth.get(user_info_url)
        return user_info.json()

    def _decode_access_token(self, token_response):
        """
        Safely decode the access token without signature verification.

        Returns:
            dict: decoded token payload, or {} if missing/invalid
        """
        access_token = token_response.get("access_token")
        if not access_token:
            log.warning("⚠️ [KEYCLOAK TOKEN] No access_token found in token response")
            return {}

        try:
            decoded = jwt.decode(
                access_token,
                options={
                    "verify_signature": False,
                    "verify_aud": False
                }
            )
            log.debug("🔓 [KEYCLOAK TOKEN] Access token decoded successfully")
            return decoded

        except PyJWTError as e:
            log.error(f"❌ [KEYCLOAK TOKEN] Error decoding JWT: {e}")
            return {}

    def log_decoded_token(self, token_response):
        """
        Debug helper to log the decoded token payload.
        Use only for debugging because tokens may contain sensitive data.
        """
        decoded = self._decode_access_token(token_response)
        if not decoded:
            log.warning("⚠️ [KEYCLOAK TOKEN] Cannot log decoded token because decoding failed")
            return

        log.info(f"🧾 [KEYCLOAK TOKEN] Decoded token payload: {decoded}")

    def extract_client_roles_from_token(self, token_response):
        """
        Extract ONLY client roles from the access_token JWT.

        Args:
            token_response: The full token response from get_token()

        Returns:
            list: Client roles for this specific client
        """
        client_roles = []

        decoded = self._decode_access_token(token_response)
        if not decoded:
            return client_roles

        try:
            resource_access = decoded.get("resource_access", {})

            if self.client_id in resource_access:
                client_roles = resource_access[self.client_id].get("roles", [])

        except Exception as e:
            log.error(f"❌ [KEYCLOAK ROLES] Unexpected error while extracting client roles: {e}")

        return client_roles

    def extract_groups_from_token(self, token_response):
        """
        Extract groups from the access_token JWT.

        Expected claim:
            "groups": ["/ckan/org/admins", "/ckan/org/members"]

        Returns:
            list: list of group paths, or [] if missing/invalid
        """
        groups = []

        decoded = self._decode_access_token(token_response)
        if not decoded:
            return groups

        try:
            raw_groups = decoded.get("groups", [])

            if isinstance(raw_groups, list):
                groups = [g for g in raw_groups if isinstance(g, str)]
            else:
                log.warning(f"⚠️ [KEYCLOAK GROUPS] 'groups' claim is not a list: {raw_groups}")
                groups = []

            log.info(f"🔥 [KEYCLOAK GROUPS] Extracted groups: {groups}")

        except Exception as e:
            log.error(f"❌ [KEYCLOAK GROUPS] Unexpected error while extracting groups: {e}")

        return groups

    def extract_organization_roles_from_groups(self, groups):
        """
        Resolve CKAN organization roles from Keycloak groups.

        Expected Keycloak group format:
            /ckan/<organization-name>/admins
            /ckan/<organization-name>/editors
            /ckan/<organization-name>/members

        Priority:
            admins > editors > members

        Returns:
            dict:
                {
                    "organization-name": "admin" | "editor" | "member"
                }

        Invalid groups are ignored and never raise an exception.
        """
        role_priority = {
            "members": 1,
            "editors": 2,
            "admins": 3
        }

        keycloak_to_ckan_role = {
            "members": "member",
            "editors": "editor",
            "admins": "admin"
        }

        org_roles = {}

        if not isinstance(groups, list):
            log.warning(f"⚠️ [KEYCLOAK GROUPS] Expected list of groups, got: {type(groups).__name__}")
            return org_roles

        for group in groups:
            try:
                if not isinstance(group, str):
                    log.warning(f"⚠️ [GROUP SKIP] Non-string group ignored: {group}")
                    continue

                parts = group.strip("/").split("/")

                # Expected: ["ckan", "<organization-name>", "<role-plural>"]
                if len(parts) != 3:
                    log.warning(f"⚠️ [GROUP SKIP] Invalid group format ignored: {group}")
                    continue

                prefix, org_name, group_role = parts

                if prefix != "ckan":
                    log.debug(f"ℹ️ [GROUP SKIP] Non-CKAN group ignored: {group}")
                    continue

                if not org_name:
                    log.warning(f"⚠️ [GROUP SKIP] Empty organization name in group: {group}")
                    continue

                if group_role not in role_priority:
                    log.warning(f"⚠️ [GROUP SKIP] Unknown CKAN role group ignored: {group}")
                    continue

                new_priority = role_priority[group_role]

                if org_name not in org_roles:
                    org_roles[org_name] = group_role
                    log.info(f"🏢 [ORG ROLE ADD] {org_name} -> {group_role}")
                else:
                    current_group_role = org_roles[org_name]
                    current_priority = role_priority[current_group_role]

                    if new_priority > current_priority:
                        log.info(
                            f"⬆️ [ORG ROLE UPGRADE] {org_name}: {current_group_role} -> {group_role}"
                        )
                        org_roles[org_name] = group_role
                    else:
                        log.info(
                            f"➡️ [ORG ROLE KEEP] {org_name}: keep {current_group_role}, ignore {group_role}"
                        )

            except Exception as e:
                log.error(f"❌ [GROUP PARSE ERROR] Failed to process group '{group}': {e}")
                continue

        final_roles = {
            org_name: keycloak_to_ckan_role[group_role]
            for org_name, group_role in org_roles.items()
        }

        log.info(f"✅ [FINAL ORG ROLES] Resolved organization roles: {final_roles}")
        return final_roles

    def extract_organization_roles_from_token(self, token_response):
        """
        Convenience method:
        Extract groups from token and resolve highest CKAN organization role per organization.

        Returns:
            dict:
                {
                    "organization-name": "admin" | "editor" | "member"
                }
        """
        groups = self.extract_groups_from_token(token_response)
        return self.extract_organization_roles_from_groups(groups)

    def extract_client_roles_from_userinfo(self, user_info):
        """
        Extract client roles from userinfo response if available.
        """
        client_roles = []

        try:
            if "resource_access" in user_info:
                resource_access = user_info["resource_access"]
                if self.client_id in resource_access:
                    client_roles = resource_access[self.client_id].get("roles", [])

            log.info(
                f"👤 [USERINFO ROLES] Extracted client roles for '{self.client_id}': {client_roles}"
            )

        except Exception as e:
            log.error(f"❌ [USERINFO ROLES] Unexpected error while extracting roles from userinfo: {e}")

        return client_roles