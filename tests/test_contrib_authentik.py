# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test case for Authentik OIDC remote app."""

from urllib.parse import parse_qs, urlparse

import pytest
from flask import session, url_for
from flask_security import login_user
from flask_security.utils import hash_password
from helpers import check_redirect_location, get_state, mock_response
from invenio_accounts.models import User
from invenio_db import db

from invenio_oauthclient.contrib.authentik import account_info_serializer
from invenio_oauthclient.handlers import token_session_key
from invenio_oauthclient.models import RemoteAccount, RemoteToken, UserIdentity


def test_account_info_serializer(app, example_authentik):
    """Test account info serialization."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]

    # Ensure remote apps have been loaded
    client.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

    example_response, example_userinfo, expected_info = example_authentik

    result = account_info_serializer(
        ioc.remote_apps["authentik"],
        example_response,
        user_info=example_userinfo,
    )

    assert result == expected_info
    assert result["external_id"] == example_userinfo["sub"]
    assert result["external_method"] == "authentik"
    assert result["user"]["email"] == example_userinfo["email"]
    assert (
        result["user"]["profile"]["username"] == example_userinfo["preferred_username"]
    )
    assert result["user"]["profile"]["full_name"] == example_userinfo["name"]


def test_account_info_serializer_missing_email(app, example_authentik):
    """Test account info serialization with missing email (uses fallback)."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]

    # Ensure remote apps have been loaded
    client.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

    example_response, example_userinfo, _ = example_authentik

    # Remove email from userinfo
    userinfo_no_email = dict(example_userinfo)
    del userinfo_no_email["email"]

    result = account_info_serializer(
        ioc.remote_apps["authentik"],
        example_response,
        user_info=userinfo_no_email,
    )

    # Should use fallback email
    assert result["user"]["email"] == f"{userinfo_no_email['sub']}@authentik.local"


def test_account_info_serializer_missing_userinfo(app):
    """Test account info serialization without user info raises error."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]

    # Ensure remote apps have been loaded
    client.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

    with pytest.raises(ValueError, match="User info is required"):
        account_info_serializer(
            ioc.remote_apps["authentik"],
            {"access_token": "test"},
            user_info=None,
        )


def test_account_info_serializer_missing_sub(app, example_authentik):
    """Test account info serialization without sub claim raises error."""
    client = app.test_client()
    ioc = app.extensions["oauthlib.client"]

    # Ensure remote apps have been loaded
    client.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

    example_response, example_userinfo, _ = example_authentik

    # Remove sub from userinfo
    userinfo_no_sub = dict(example_userinfo)
    del userinfo_no_sub["sub"]

    with pytest.raises(ValueError, match="Subject identifier .* is required"):
        account_info_serializer(
            ioc.remote_apps["authentik"],
            example_response,
            user_info=userinfo_no_sub,
        )


def test_login(app):
    """Test Authentik login."""
    client = app.test_client()

    resp = client.get(
        url_for(
            "invenio_oauthclient.login",
            remote_app="authentik",
            next="/someurl/",
        )
    )
    assert resp.status_code == 302

    params = parse_qs(urlparse(resp.location).query)
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid profile email"]
    assert params["redirect_uri"]
    assert params["client_id"]
    assert params["state"]


def test_authorized_signup(app_with_userprofiles, example_authentik):
    """Test authorized callback with sign-up."""
    app = app_with_userprofiles
    example_response, example_userinfo, expected_info = example_authentik
    example_email = "jsmith@example.com"

    with app.test_client() as c:
        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

        # Mock the OAuth response
        ioc = app.extensions["oauthlib.client"]
        mock_remote = ioc.remote_apps["authentik"]
        mock_response(ioc, "authentik", example_response)

        # Mock the userinfo endpoint
        mock_remote.get = lambda url: type(
            "obj",
            (object,),
            {
                "data": example_userinfo,
                "_resp": type("obj", (object,), {"code": 200}),
            },
        )()

        # User authorized the requests and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="authentik",
                code="test",
                state=get_state("authentik"),
            )
        )
        assert resp.status_code == 302
        check_redirect_location(
            resp, url_for("invenio_oauthclient.signup", remote_app="authentik")
        )

        # User loads sign-up page
        resp = c.get(url_for("invenio_oauthclient.signup", remote_app="authentik"))
        assert resp.status_code == 200

        account_info_data = session[token_session_key("authentik") + "_account_info"]
        assert account_info_data["external_id"] == example_userinfo["sub"]

        # User fills form to register
        data = {
            "email": example_email,
            "password": "123456",
            "profile.username": account_info_data["user"]["profile"]["username"],
            "profile.full_name": account_info_data["user"]["profile"]["full_name"],
        }

        resp = c.post(
            url_for("invenio_oauthclient.signup", remote_app="authentik"),
            data=data,
        )
        assert resp.status_code == 302
        check_redirect_location(resp, "/")

        # Assert database state (Sign-up complete)
        user = User.query.filter_by(email=example_email).one()
        remote_account = RemoteAccount.query.filter_by(user_id=user.id).one()
        RemoteToken.query.filter_by(
            id_remote_account=remote_account.id,
            access_token=example_response["access_token"],
        ).one()

        # Check UserIdentity
        UserIdentity.query.filter_by(
            method="authentik",
            id_user=user.id,
            id=example_userinfo["sub"],
        ).one()

        # Check that the user profile was set correctly
        assert user.user_profile["username"] == data["profile.username"]
        assert user.user_profile["full_name"] == data["profile.full_name"]

        # User should be active
        assert user.active


def test_authorized_signup_with_auto_signup(app, example_authentik):
    """Test authorized callback with auto sign-up enabled."""
    app.config["OAUTHCLIENT_REMOTE_APPS"]["authentik"]["signup_options"][
        "auto_confirm"
    ] = True

    example_response, example_userinfo, expected_info = example_authentik

    with app.test_client() as c:
        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

        # Mock the OAuth response
        ioc = app.extensions["oauthlib.client"]
        mock_remote = ioc.remote_apps["authentik"]
        mock_response(ioc, "authentik", example_response)

        # Mock the userinfo endpoint
        mock_remote.get = lambda url: type(
            "obj",
            (object,),
            {
                "data": example_userinfo,
                "_resp": type("obj", (object,), {"code": 200}),
            },
        )()

        # User authorized the requests and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="authentik",
                code="test",
                state=get_state("authentik"),
            )
        )
        assert resp.status_code == 302
        assert resp.location == "/"

        # Assert database state (Sign-up complete with email from Authentik)
        user = User.query.filter_by(email=example_userinfo["email"]).one()
        assert user.active


def test_authorized_already_authenticated(app, models_fixture, example_authentik):
    """Test authorized callback when user is already authenticated."""
    example_response, example_userinfo, expected_info = example_authentik

    datastore = app.extensions["security"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    with app.test_client() as c:
        login_user(user)

        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

        # Mock the OAuth response
        ioc = app.extensions["oauthlib.client"]
        mock_remote = ioc.remote_apps["authentik"]
        mock_response(ioc, "authentik", example_response)

        # Mock the userinfo endpoint
        mock_remote.get = lambda url: type(
            "obj",
            (object,),
            {
                "data": example_userinfo,
                "_resp": type("obj", (object,), {"code": 200}),
            },
        )()

        # User authorized the requests and is redirected back
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="authentik",
                code="test",
                state=get_state("authentik"),
            )
        )
        assert resp.status_code == 302
        assert resp.location == "/"

        # Assert that remote account was linked
        remote_account = RemoteAccount.query.filter_by(user_id=user.id).one()
        assert remote_account.extra_data["sub"] == example_userinfo["sub"]
        assert remote_account.extra_data["email"] == example_userinfo["email"]

        # Check UserIdentity
        UserIdentity.query.filter_by(
            method="authentik",
            id_user=user.id,
            id=example_userinfo["sub"],
        ).one()


def test_account_setup_stores_extra_data(app, models_fixture, example_authentik):
    """Test that account setup stores all relevant data."""
    example_response, example_userinfo, expected_info = example_authentik

    datastore = app.extensions["security"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    with app.test_client() as c:
        login_user(user)

        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

        # Mock the OAuth response
        ioc = app.extensions["oauthlib.client"]
        mock_remote = ioc.remote_apps["authentik"]
        mock_response(ioc, "authentik", example_response)

        # Mock the userinfo endpoint with optional fields
        userinfo_with_extras = dict(example_userinfo)
        userinfo_with_extras.update(
            {
                "given_name": "John",
                "family_name": "Smith",
                "groups": ["group1", "group2"],
                "picture": "https://example.com/avatar.jpg",
            }
        )

        mock_remote.get = lambda url: type(
            "obj",
            (object,),
            {
                "data": userinfo_with_extras,
                "_resp": type("obj", (object,), {"code": 200}),
            },
        )()

        # User authorized the requests
        c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="authentik",
                code="test",
                state=get_state("authentik"),
            )
        )

        # Check that extra data was stored
        remote_account = RemoteAccount.query.filter_by(user_id=user.id).one()
        assert remote_account.extra_data["sub"] == userinfo_with_extras["sub"]
        assert remote_account.extra_data["email"] == userinfo_with_extras["email"]
        assert remote_account.extra_data["given_name"] == "John"
        assert remote_account.extra_data["family_name"] == "Smith"
        assert remote_account.extra_data["groups"] == ["group1", "group2"]
        assert remote_account.extra_data["picture"] == userinfo_with_extras["picture"]


def test_disconnect(app, models_fixture, example_authentik):
    """Test disconnect functionality."""
    example_response, example_userinfo, expected_info = example_authentik

    datastore = app.extensions["security"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    with app.test_client() as c:
        # Setup user with password so they have alternative login
        user.password = hash_password("123456")
        db.session.commit()

        login_user(user)

        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

        # Mock the OAuth response
        ioc = app.extensions["oauthlib.client"]
        mock_remote = ioc.remote_apps["authentik"]
        mock_response(ioc, "authentik", example_response)

        # Mock the userinfo endpoint
        mock_remote.get = lambda url: type(
            "obj",
            (object,),
            {
                "data": example_userinfo,
                "_resp": type("obj", (object,), {"code": 200}),
            },
        )()

        # Connect the account
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="authentik",
                code="test",
                state=get_state("authentik"),
            )
        )
        assert resp.status_code == 302

        # Verify account is connected
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 1
        assert (
            UserIdentity.query.filter_by(method="authentik", id_user=user.id).count()
            == 1
        )

        # Disconnect
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="authentik"))
        assert resp.status_code == 302

        # Verify account is disconnected
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 0
        assert (
            UserIdentity.query.filter_by(method="authentik", id_user=user.id).count()
            == 0
        )


def test_disconnect_without_alternative_login(app, models_fixture, example_authentik):
    """Test that disconnect fails when user has no alternative login method."""
    example_response, example_userinfo, expected_info = example_authentik

    datastore = app.extensions["security"].datastore
    existing_email = "existing@inveniosoftware.org"
    user = datastore.find_user(email=existing_email)

    with app.test_client() as c:
        login_user(user)

        # Ensure remote apps have been loaded
        c.get(url_for("invenio_oauthclient.login", remote_app="authentik"))

        # Mock the OAuth response
        ioc = app.extensions["oauthlib.client"]
        mock_remote = ioc.remote_apps["authentik"]
        mock_response(ioc, "authentik", example_response)

        # Mock the userinfo endpoint
        mock_remote.get = lambda url: type(
            "obj",
            (object,),
            {
                "data": example_userinfo,
                "_resp": type("obj", (object,), {"code": 200}),
            },
        )()

        # Connect the account
        resp = c.get(
            url_for(
                "invenio_oauthclient.authorized",
                remote_app="authentik",
                code="test",
                state=get_state("authentik"),
            )
        )
        assert resp.status_code == 302

        # Verify account is connected
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 1

        # Try to disconnect - should fail (no password set)
        resp = c.get(url_for("invenio_oauthclient.disconnect", remote_app="authentik"))
        assert resp.status_code == 400

        # Verify account is still connected
        assert RemoteAccount.query.filter_by(user_id=user.id).count() == 1
