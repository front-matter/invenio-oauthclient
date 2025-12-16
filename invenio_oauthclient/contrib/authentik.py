# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025 Front Matter.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with Authentik.

Authentik is an open-source Identity Provider focused on flexibility and
versatility. It supports OAuth2, OpenID Connect, SAML, and more.

1. Edit your configuration and add:

   .. code-block:: python

        from invenio_oauthclient.contrib import authentik

        OAUTHCLIENT_REMOTE_APPS = dict(
            authentik=authentik.REMOTE_APP,
        )

        AUTHENTIK_APP_CREDENTIALS = dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        )

2. Register a new OAuth2/OpenID Provider application in your Authentik
   instance. When registering the application ensure that the
   *Redirect URIs* includes:
   ``http://localhost:5000/oauth/authorized/authentik/``

   For production deployments:
   ``https://yourdomain.com/oauth/authorized/authentik/``

3. Configure the application in Authentik:
   - Provider type: OAuth2/OpenID Provider
   - Client type: Confidential
   - Authorization grant type: Authorization Code
   - Redirect URIs: Add your callback URL
   - Scopes: openid profile email

4. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        AUTHENTIK_APP_CREDENTIALS = dict(
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

5. Configure the Authentik base URL in your configuration:

   Via Flask configuration:

   .. code-block:: python

        AUTHENTIK_BASE_URL = 'https://your-authentik-instance.com'

   Or via environment variable:

   .. code-block:: bash

        export AUTHENTIK_BASE_URL='https://your-authentik-instance.com'

   Configuration is checked in the following priority order:
   1. Flask app config (current_app.config['AUTHENTIK_BASE_URL'])
   2. Environment variable (AUTHENTIK_BASE_URL)
   3. Default value (http://localhost:9000)

   The module will automatically discover OAuth/OIDC endpoints using the
   OpenID Connect Discovery specification (.well-known/openid-configuration).
   If discovery fails, it falls back to default Authentik endpoint paths.

6. Now go to your site: http://localhost:5000/oauth/login/authentik/

7. You should see Authentik listed under Linked accounts:
   http://localhost:5000/account/settings/linkedaccounts/

In case you would prefer a different title and description for this app
you can re-define the default Authentik OAuth instance:

.. code-block:: python

        from invenio_oauthclient.contrib import authentik

        _my_app = authentik.AuthentikOAuthSettingsHelper(
            title="My Authentik",
            description="Custom description",
            base_url="https://your-authentik-instance.com",
            use_discovery=True  # Enable OIDC discovery (default)
        )

        OAUTHCLIENT_REMOTE_APPS = dict(
            authentik=_my_app.remote_app,
        )

        AUTHENTIK_APP_CREDENTIALS = dict(
            consumer_key='changeme',
            consumer_secret='changeme',
        )

Note: The module supports OpenID Connect Discovery (RFC 8414) to automatically
configure endpoints. Set `use_discovery=False` if you want to manually specify
endpoints or if your Authentik instance doesn't support discovery.
"""

import os

import os

import os

import requests
from flask import current_app, redirect, url_for
from flask_login import current_user
from invenio_db import db
from invenio_i18n import lazy_gettext as _

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id

# Cache for OIDC discovery documents
_discovery_cache = {}


class AuthentikOAuthSettingsHelper(OAuthSettingsHelper):
    """Default configuration for Authentik OAuth provider."""

    def __init__(
        self,
        title=None,
        description=None,
        base_url=None,
        app_key=None,
        access_token_url=None,
        authorize_url=None,
        logout_url=None,
        precedence_mask=None,
        signup_options=None,
        use_discovery=True,
    ):
        """Constructor.

        :param use_discovery: Whether to use OIDC discovery to auto-configure
                            endpoints. Defaults to True.
        """
        # Use provided base_url or default
        # Don't access current_app.config here to avoid runtime issues
        if base_url is None:
            base_url = "http://localhost:9000"

        # Ensure base_url doesn't have trailing slash for proper URL construction
        base_url = base_url.rstrip("/")

        # Try OIDC discovery if enabled and no explicit URLs provided
        if use_discovery and not all([access_token_url, authorize_url]):
            try:
                discovery_doc = self._fetch_oidc_discovery(base_url)
                if discovery_doc:
                    access_token_url = access_token_url or discovery_doc.get(
                        "token_endpoint"
                    )
                    authorize_url = authorize_url or discovery_doc.get(
                        "authorization_endpoint"
                    )
                    logout_url = logout_url or discovery_doc.get("end_session_endpoint")
            except Exception as e:
                # Log warning but continue with manual configuration
                try:
                    current_app.logger.warning(
                        f"OIDC discovery failed for {base_url}: {str(e)}. "
                        f"Using manual endpoint configuration."
                    )
                except RuntimeError:
                    # No app context, silently continue
                    pass

        # Construct OIDC endpoints (fallback if discovery failed or disabled)
        access_token_url = access_token_url or f"{base_url}/application/o/token/"
        authorize_url = authorize_url or f"{base_url}/application/o/authorize/"
        logout_url = logout_url or f"{base_url}/application/o/endsession/"

        precedence_mask = precedence_mask or {
            "email": True,
            "profile": {
                "username": True,
                "full_name": True,
            },
        }

        signup_options = signup_options or {
            "auto_confirm": True,
            "send_register_msg": False,
        }

        super().__init__(
            title or _("Authentik"),
            description or _("Identity provider for modern applications."),
            base_url=base_url,
            app_key=app_key or "AUTHENTIK_APP_CREDENTIALS",
            request_token_params={"scope": "openid profile email"},
            access_token_url=access_token_url,
            authorize_url=authorize_url,
            logout_url=logout_url,
            content_type="application/json",
            precedence_mask=precedence_mask,
            signup_options=signup_options,
        )

        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.authentik:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.authentik:account_info",
                info_serializer="invenio_oauthclient.contrib.authentik:account_info_serializer",
                setup="invenio_oauthclient.contrib.authentik:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.authentik:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.authentik:account_info",
                info_serializer="invenio_oauthclient.contrib.authentik:account_info_serializer",
                setup="invenio_oauthclient.contrib.authentik:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler="invenio_oauthclient.handlers.rest:default_remote_response_handler",
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    def get_handlers(self):
        """Return Authentik auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return Authentik auth REST handlers."""
        return self._rest_handlers

    @property
    def userinfo_url(self):
        """Return the URL to fetch user info."""
        return f"{self.base_url}/application/o/userinfo/"

    @property
    def discovery_url(self):
        """Return the OIDC discovery URL."""
        return f"{self.base_url}/application/o/.well-known/openid-configuration"

    @staticmethod
    def _fetch_oidc_discovery(base_url):
        """Fetch and cache OIDC discovery document.

        :param base_url: The base URL of the Authentik instance.
        :returns: Dictionary containing the discovery document or None.
        """
        # Check cache first
        if base_url in _discovery_cache:
            return _discovery_cache[base_url]

        discovery_url = f"{base_url}/application/o/.well-known/openid-configuration"

        try:
            response = requests.get(discovery_url, timeout=10)
            response.raise_for_status()
            discovery_doc = response.json()

            # Validate required fields
            required_fields = [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
            ]

            if not all(field in discovery_doc for field in required_fields):
                raise ValueError(
                    f"Discovery document missing required fields: {required_fields}"
                )

            # Cache the discovery document
            _discovery_cache[base_url] = discovery_doc
            return discovery_doc

        except (requests.RequestException, ValueError):
            # Return None to trigger fallback to manual configuration
            return None


def _get_authentik_app():
    """Get or create Authentik app instance with runtime configuration.

    This function allows for lazy initialization to access current_app.config
    at runtime instead of module import time. Configuration priority:
    1. Flask app config (current_app.config['AUTHENTIK_BASE_URL'])
    2. Environment variable (AUTHENTIK_BASE_URL)
    3. Default value (http://localhost:9000)
    """
    try:
        # Try to get base_url from config at runtime if available
        base_url = current_app.config.get(
            "AUTHENTIK_BASE_URL",
            os.environ.get("AUTHENTIK_BASE_URL", "http://localhost:9000"),
        )
    except RuntimeError:
        # No app context available, try environment variable then default
        base_url = os.environ.get("AUTHENTIK_BASE_URL", "http://localhost:9000")

    return AuthentikOAuthSettingsHelper(base_url=base_url)


_authentik_app = AuthentikOAuthSettingsHelper()

BASE_APP = _authentik_app.base_app
"""Authentik base application configuration."""

REMOTE_APP = _authentik_app.remote_app
"""Authentik remote application configuration."""

REMOTE_REST_APP = _authentik_app.remote_rest_app
"""Authentik remote REST application configuration."""


def get_user_info(remote):
    """Get user information from Authentik userinfo endpoint.

    See the Authentik documentation for the OIDC userinfo endpoint:
    https://goauthentik.io/docs/

    :param remote: The remote application.
    :returns: User information dictionary.
    :raises OAuthResponseError: If the request fails or response is invalid.
    """
    try:
        # Get userinfo URL with runtime config support
        app = _get_authentik_app()
        userinfo_url = app.userinfo_url
        response = remote.get(userinfo_url)

        if getattr(response, "_resp", None) and response._resp.code >= 400:
            raise OAuthResponseError(
                _("Failed to fetch user information from Authentik"),
                None,
                response,
            )

        user_info = response.data

        # Validate required OIDC fields
        if "sub" not in user_info:
            raise OAuthResponseError(
                _("Missing subject identifier in user info"),
                None,
                response,
            )

        return user_info

    except Exception as e:
        if isinstance(e, OAuthResponseError):
            raise
        current_app.logger.error(f"Failed to fetch user info from Authentik: {str(e)}")
        raise OAuthResponseError(
            _("Failed to fetch user information"), None, None
        ) from e


def account_info_serializer(remote, resp, user_info=None, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param user_info: User info from userinfo endpoint.
    :returns: A dictionary with serialized user information.
    """
    if not user_info:
        raise ValueError("User info is required for account serialization")

    # Extract external ID from 'sub' claim (standard OIDC)
    external_id = user_info.get("sub")
    if not external_id:
        raise ValueError("Subject identifier (sub) is required")

    # Extract email with fallback
    email = user_info.get("email")
    if not email:
        current_app.logger.warning(
            "No email provided by Authentik, using sub as fallback"
        )
        email = f"{external_id}@authentik.local"

    # Extract username with fallbacks
    username = (
        user_info.get("preferred_username")
        or user_info.get("nickname")
        or user_info.get("sub")
    )

    # Extract full name with fallback
    full_name = user_info.get("name", "")
    if not full_name and user_info.get("given_name"):
        full_name = " ".join(
            filter(
                None,
                [user_info.get("given_name"), user_info.get("family_name")],
            )
        )

    return {
        "external_id": external_id,
        "external_method": remote.name,
        "user": {
            "email": email,
            "profile": {
                "username": username,
                "full_name": full_name,
            },
        },
    }


def account_info(remote, resp):
    """Retrieve remote account information used to find local user.

    It returns a dictionary with the following structure:

    .. code-block:: python

        {
            'user': {
                'email': '...',
                'profile': {
                    'username': '...',
                    'full_name': '...',
                },
            },
            'external_id': 'authentik-sub-claim',
            'external_method': 'authentik',
        }

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    try:
        user_info = get_user_info(remote)

        handlers = current_oauthclient.signup_handlers[remote.name]
        # `remote` param automatically injected via `make_handler` helper
        return handlers["info_serializer"](resp, user_info=user_info)

    except Exception as e:
        current_app.logger.error(f"Failed to get account info: {str(e)}")
        raise


def account_setup(remote, token, resp):
    """Perform additional setup after user has been logged in.

    :param remote: The remote application.
    :param token: The token value.
    :param resp: The response.
    """
    try:
        user_info = get_user_info(remote)

        with db.session.begin_nested():
            # Store comprehensive user data in extra_data
            extra_data = {
                "sub": user_info.get("sub"),
                "email": user_info.get("email"),
                "full_name": user_info.get("name", ""),
                "username": (
                    user_info.get("preferred_username")
                    or user_info.get("nickname")
                    or ""
                ),
            }

            # Store optional fields if present
            optional_fields = [
                "given_name",
                "family_name",
                "nickname",
                "preferred_username",
                "groups",
                "picture",
            ]
            for field in optional_fields:
                if field in user_info:
                    extra_data[field] = user_info[field]

            token.remote_account.extra_data = extra_data

            # Create user <-> external id link using 'sub' claim
            external_id = user_info.get("sub")
            if external_id:
                oauth_link_external_id(
                    token.remote_account.user,
                    dict(id=external_id, method=remote.name),
                )

    except Exception as e:
        current_app.logger.error(f"Account setup failed: {str(e)}")
        db.session.rollback()
        raise


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    """
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )

    # Remove external ID links
    external_ids = [
        i.id for i in current_user.external_identifiers if i.method == remote.name
    ]

    if external_ids:
        oauth_unlink_external_id(dict(id=external_ids[0], method=remote.name))

    if account:
        with db.session.begin_nested():
            account.delete()


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The HTML response.
    """
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    :returns: The JSON response.
    """
    _disconnect(remote, *args, **kwargs)
    redirect_url = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name][
        "disconnect_redirect_url"
    ]
    return response_handler(remote, redirect_url)
