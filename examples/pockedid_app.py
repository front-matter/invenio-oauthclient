# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2025 Front Matter.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

r"""Minimal Flask application example for development with pocketid handler.

SPHINX-START

1. Register a Pocket ID application with the
   `Redirect URL` as `http://localhost:5000/oauth/authorized/pocketid/`.


2. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration as `consumer_key` and
   `consumer_secret`.

   .. code-block:: console

       $ export POCKETID_APP_CREDENTIALS_KEY=my_pocketid_client_id
       $ export POCKETID_APP_CREDENTIALS_SECRET=my_pocketid_client_secret

3. Create database and tables:

   .. code-block:: console

       $ cdvirtualenv src/invenio-oauthclient
       $ pip install -e .[all]
       $ cd examples
       $ export FLASK_APP=pocketid_app.py
       $ ./app-setup.sh

You can find the database in `examples/pocketid_app.db`.

4. Run the development server:

   .. code-block:: console

       $ flask run -p 5000 -h '0.0.0.0'

5. Open in a browser the page `http://localhost:5000/oauth/login/pocketid/`.

   You will be redirected to pocketid to authorize the application.

   Click on `Allow` and you will be redirected back to
   `http://localhost:5000/oauth/signup/pocketid/`, where you will be able to
   finalize the local user registration.

6. To clean up and drop tables:

   .. code-block:: console

       $ ./app-teardown.sh

SPHINX-END

"""

import os

from flask import Flask, redirect, url_for
from flask_login import current_user
from flask_menu import Menu as FlaskMenu
from invenio_accounts import InvenioAccounts
from invenio_accounts.views import blueprint as blueprint_user
from invenio_db import InvenioDB
from invenio_i18n import Babel
from invenio_mail import InvenioMail
from invenio_userprofiles import InvenioUserProfiles
from invenio_userprofiles.views import blueprint_ui_init as blueprint_userprofile_init

from invenio_oauthclient import InvenioOAuthClient
from invenio_oauthclient.contrib import pocketid
from invenio_oauthclient.views.client import blueprint as blueprint_client
from invenio_oauthclient.views.settings import blueprint as blueprint_settings

from invenio_oauthclient._compat import monkey_patch_werkzeug  # noqa isort:skip

monkey_patch_werkzeug()  # noqa isort:skip
from flask_oauthlib.client import OAuth as FlaskOAuth  # noqa isort:skip

# [ Configure application credentials ]
POCKETID_APP_CREDENTIALS = dict(
    consumer_key=os.environ.get("POCKETID_APP_CREDENTIALS_KEY"),
    consumer_secret=os.environ.get("POCKETID_APP_CREDENTIALS_SECRET"),
)

# Create Flask application
app = Flask(__name__)

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite:///pocketid_app.db"
    ),
    OAUTHCLIENT_REMOTE_APPS=dict(
        pocketid=pocketid.REMOTE_APP,
    ),
    POCKETID_APP_CREDENTIALS=POCKETID_APP_CREDENTIALS,
    DEBUG=True,
    SECRET_KEY="TEST",
    SQLALCHEMY_ECHO=False,
    SECURITY_PASSWORD_SALT="security-password-salt",
    MAIL_SUPPRESS_SEND=True,
    TESTING=True,
    USERPROFILES_EXTEND_SECURITY_FORMS=True,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    APP_THEME=["semantic-ui"],
    THEME_ICONS={"semantic-ui": dict(link="linkify icon")},
)

Babel(app)
FlaskMenu(app)
InvenioDB(app)
InvenioAccounts(app)
InvenioUserProfiles(app)
FlaskOAuth(app)
InvenioOAuthClient(app)
InvenioMail(app)

app.register_blueprint(blueprint_user)
app.register_blueprint(blueprint_client)
app.register_blueprint(blueprint_settings)
app.register_blueprint(blueprint_userprofile_init)


@app.route("/")
def index():
    """Homepage."""
    return "Home page (without any restrictions)"


@app.route("/pocketid")
def pocketid():
    """Try to print user email or redirect to login with pocketid."""
    if not current_user.is_authenticated:
        return redirect(url_for("invenio_oauthclient.login", remote_app="pocketid"))
    return "hello {}".format(current_user.email)
