# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025 Front Matter.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with Pocket ID.

1. Edit your configuration and add:

   .. code-block:: python

       from invenio_oauthclient.contrib import pocketid

       OAUTHCLIENT_REMOTE_APPS = dict(
           pocketid=pocketid.REMOTE_APP,
       )

       POCKETID_APP_CREDENTIALS = dict(
           consumer_key="changeme",
           consumer_secret="changeme",
       )

2. Register a new application with Pocket ID. When registering the
   application ensure that the *Redirect URI* points to:
   ``CFG_SITE_URL/oauth/authorized/pocketid/``.


3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

       POCKETID_APP_CREDENTIALS = dict(
           consumer_key="<CLIENT ID>",
           consumer_secret="<CLIENT SECRET>",
       )

4. Now go to ``CFG_SITE_URL/oauth/login/pocketid/`` (e.g.
   http://localhost:4000/oauth/login/pocketid/)

5. Also, you should see Pocket ID listed under Linked accounts:
   http://localhost:4000/account/settings/linkedaccounts/

By default the Pocket ID module will try first look if a link already exists
between a Pocket ID account and a user. If no link is found, the user is asked
to provide an email address to sign-up.

In templates you can add a sign in/up link:

.. code-block:: jinja

    <a href="{{url_for('invenio_oauthclient.login', remote_app='pocketid')}}">
      Sign in with Pocket ID
    </a>

"""

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


class PocketIDOAuthSettingsHelper(OAuthSettingsHelper):
    """Default configuration for Pocket ID OAuth provider."""

    def __init__(
        self,
        title=None,
        description=None,
        base_url=None,
        app_key=None,
        access_token_url=None,
        authorize_url=None,
        precedence_mask=None,
        signup_options=None,
    ):
        """Constructor."""
        # Set base_url first
        base_url = base_url or "https://demo.pocket-id.org/"

        precedence_mask = precedence_mask or {
            "email": True,
        }
        signup_options = signup_options or {
            "auto_confirm": True,
            "send_register_msg": False,
        }

        super().__init__(
            title or _("Pocket ID"),
            description
            or _(
                "A simple and easy-to-use OIDC provider that allows users to authenticate with their passkeys to your services."
            ),
            app_key=app_key or "POCKETID_APP_CREDENTIALS",
            base_url=base_url,
            request_token_params={"scope": "openid profile email groups"},
            access_token_url=access_token_url or f"{base_url}api/oidc/token",
            authorize_url=authorize_url or f"{base_url}authorize",
            content_type="application/json",
            precedence_mask=precedence_mask,
            signup_options=signup_options,
        )

        self._handlers = dict(
            authorized_handler="invenio_oauthclient.handlers:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.pocketid:disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.pocketid:account_info",
                info_serializer="invenio_oauthclient.contrib.pocketid:account_info_serializer",
                setup="invenio_oauthclient.contrib.pocketid:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

        self._rest_handlers = dict(
            authorized_handler="invenio_oauthclient.handlers.rest:authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.pocketid:disconnect_rest_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.pocketid:account_info",
                info_serializer="invenio_oauthclient.contrib.pocketid:account_info_serializer",
                setup="invenio_oauthclient.contrib.pocketid:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler="invenio_oauthclient.handlers.rest:default_remote_response_handler",
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
        )

    @property
    def user_info_url(self):
        """Return the URL to fetch user info."""
        return f"{self.base_url}api/oidc/userinfo"

    def get_handlers(self):
        """Return Pocket ID auth handlers."""
        return self._handlers

    def get_rest_handlers(self):
        """Return Pocket ID auth REST handlers."""
        return self._rest_handlers


_pocketid_app = PocketIDOAuthSettingsHelper()

BASE_APP = _pocketid_app.base_app
REMOTE_APP = _pocketid_app.remote_app
"""Pocket ID Remote Application."""

REMOTE_REST_APP = _pocketid_app.remote_rest_app
"""Pocket ID Remote REST Application."""


def get_user_info(remote):
    """Get user information from Pocket ID userinfo endpoint.

    :param remote: The remote application.
    :returns: User information dictionary.
    """
    try:
        response = remote.get(_pocketid_app.user_info_url)

        if response.status_code >= 400:
            raise OAuthResponseError(
                _("Failed to fetch user information from Pocket ID"), None, response
            )

        user_info = response.data

        # Validate required OIDC fields
        if "sub" not in user_info:
            raise OAuthResponseError(
                _("Missing subject identifier in user info"), None, response
            )

        return user_info

    except Exception as e:
        if isinstance(e, OAuthResponseError):
            raise
        current_app.logger.error(f"Failed to fetch user info from Pocket ID: {str(e)}")
        raise OAuthResponseError(
            _("Failed to fetch user information"), None, None
        ) from e


def account_info_serializer(remote, resp, user_info, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    return {
        "external_id": user_info["sub"],
        "external_method": remote.name,
        "user": {
            "profile": {
                "full_name": user_info.get("name"),
            },
            "email": user_info.get("email"),
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
            'external_id': 'pocket-id-sub-claim',
            'external_method': 'pocketid',
        }

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    user_info_url = f"{remote.base_url}oidc/userinfo"
    user_info = remote.get(user_info_url).data

    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["info_serializer"](resp, user_info)


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
    """
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account.

    :param remote: The remote application.
    """
    _disconnect(remote, *args, **kwargs)
    redirect_url = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name][
        "disconnect_redirect_url"
    ]
    return response_handler(remote, redirect_url)


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in.

    :param remote: The remote application.
    :param token: The token value.
    :param resp: The response.
    """
    try:
        user_info = get_user_info(remote)

        with db.session.begin_nested():
            # Store comprehensive user data
            token.remote_account.extra_data = {
                "sub": user_info.get("sub"),
                "email": user_info.get("email"),
                "full_name": user_info.get("name", ""),
                "username": user_info.get("preferred_username", ""),
                "groups": user_info.get("groups", []),
            }

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
