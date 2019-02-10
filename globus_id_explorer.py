#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, url_for, session, redirect, request, render_template
import globus_sdk
from globus_sdk import (GlobusError,GlobusAPIError)
import json
import time


app = Flask(__name__)
app.config.from_pyfile('globus_id_explorer.conf')

@app.route('/')
def index():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    # If not logged in, welcome and invite to login
    if not session.get('is_authenticated'):
         return render_template('not-logged-in.html',
                                pagetitle=app.config['APP_DISPLAY_NAME'],
                                loginurl=url_for('login'),
                                loginstat=loginstatus)

    # get the stored access token for the Auth API and use it
    # to authorize stuff AS THE AUTHENTICATED USER
    auth_token = str(session.get('auth_token'))
    ac = globus_sdk.AuthClient(authorizer=globus_sdk.AccessTokenAuthorizer(auth_token))

    try:
         # use Auth API to get more info about the authenticated user
         myids = ac.get_identities(ids=str(session.get('userid')),include="identity_provider").data

         # use Auth API to get the standard OIDC userinfo fields (like any OIDC client)
         oidcinfo = ac.oauth2_userinfo()

         # get the stored OIDC id_token
         myoidc = session.get('id_token')

         # authenticate to Auth API AS AN APPLICATION and find out still more information
         cc = load_app_client()
         ir = cc.oauth2_token_introspect(auth_token,include='identities_set,session_info').data
    except GlobusAPIError:
         # if any of the above have issues, trash the session and start over
         session.clear()
         return redirect(url_for('index'))

    # use session data to find out how the user authenticated
    authevents = get_auth_events(ir,oidcinfo)

    # display all this information on the web page
    return render_template('logged-in.html',
         pagetitle=app.config['APP_DISPLAY_NAME'],
         authevents=authevents,
         oidcexplanationurl=url_for('oidc_explanation'),
         oidcname=oidcinfo["name"],
         oidcemail=oidcinfo["email"],
         oidcprefname=oidcinfo["preferred_username"],
         oidcsub=oidcinfo["sub"],
         id_token=json.dumps(myoidc,indent=3),
         oidcinfo=json.dumps(oidcinfo.data,indent=3),
         globusexplanationurl=url_for('globus_explanation'),
         globusmyids=json.dumps(myids,indent=3),
         globusintrores=json.dumps(ir,indent=3),
         loginstat=loginstatus)

@app.route('/login')
def login():
    """
    Login via Globus Auth.
    May be invoked in one of two scenarios:

      1. Login is starting, no state in Globus Auth yet
      2. Returning to application during login, already have short-lived
         code from Globus Auth to exchange for tokens, encoded in a query
         param
    """
    # the redirect URI, as a complete URI (not relative path)
    redirect_uri = url_for('login', _external=True)

    auth_client = load_app_client()
    auth_client.oauth2_start_flow(redirect_uri, 
            requested_scopes='openid email profile urn:globus:auth:scope:auth.globus.org:view_identity_set')

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:
        auth_uri = auth_client.oauth2_get_authorize_url()
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        code = request.args.get('code')
        tokens_response = auth_client.oauth2_exchange_code_for_tokens(code)

        # Get the id_token (ids) that tells us who this user is (for the login/logout display)
        id_token = tokens_response.decode_id_token()

        # Get the Search API token (for authenticating Search API requests)
        auth_token_data = tokens_response.by_resource_server['auth.globus.org']
        AUTH_TOKEN = auth_token_data['access_token']

        session.update(
                auth_token=AUTH_TOKEN,
                id_token=id_token,
                userid=id_token['sub'],
                identity=id_token['preferred_username'],
                fullname=id_token['name'],
                is_authenticated=True
                )
        return redirect(url_for('index'))

@app.route("/logout")
def logout():
    """
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """

    # Destroy the session state
    session.clear()

    # the return redirection location to give to Globus AUth
    redirect_uri = url_for('index', _external=True)

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client_id={}'.format(app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(redirect_uri) +
        '&redirect_name={}'.format(app.config['APP_DISPLAY_NAME']))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)

@app.route("/oidc-explanation")
def oidc_explanation():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    # If not logged in, welcome and invite to login
    if not session.get('is_authenticated'):
         return render_template('not-logged-in.html',
                                pagetitle=app.config['APP_DISPLAY_NAME'],
                                loginurl=url_for('login'),
                                loginstat=loginstatus)

    # get the id_token from session context
    myoidc = session.get('id_token')
    primaryidp = myoidc['identity_provider_display_name'];

    # get the stored access token for the Auth API and use it
    # to authorize stuff AS THE AUTHENTICATED USER
    auth_token = str(session.get('auth_token'))
    ac = globus_sdk.AuthClient(authorizer=globus_sdk.AccessTokenAuthorizer(auth_token))

    # get the identity_set from oauth2_userinfo()
    try:
         # use Auth API to get more info about the authenticated user
         myids = ac.get_identities(ids=str(session.get('userid')),include="identity_provider").data

         # use Auth API to get the standard OIDC userinfo fields (like any OIDC client)
         oidcinfo = ac.oauth2_userinfo()
    except GlobusAPIError:
         # if any of the above have issues, trash the session and start over
         session.clear()
         return redirect(url_for('index'))

    # there will always be at least one entry in the identity_set
    idsetproviders = ''
    first = True
    for id in oidcinfo.data['identity_set']:
         if first:
              first = False
         else:
              idsetproviders += ', '
         idsetproviders += id['identity_provider_display_name']
    return render_template('oidc-explanation.html',
                           pagetitle=app.config['APP_DISPLAY_NAME'],
                           returnurl=url_for('index'),
                           primaryidp=primaryidp,
                           idsetproviders=idsetproviders,
                           loginstat=loginstatus)

@app.route("/globus-explanation")
def globus_explanation():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    # If not logged in, welcome and invite to login
    if not session.get('is_authenticated'):
         return render_template('not-logged-in.html',
                                pagetitle=app.config['APP_DISPLAY_NAME'],
                                loginurl=url_for('login'),
                                loginstat=loginstatus)

    # get the id_token from session context
    myoidc = session.get('id_token')
    primaryidp = myoidc['identity_provider_display_name'];

    return render_template('globus-explanation.html',
                           pagetitle=app.config['APP_DISPLAY_NAME'],
                           returnurl=url_for('index'),
                           primaryidp=primaryidp,
                           loginstat=loginstatus)

@app.route("/privacy")
def privacy():
    # Call get_login_status() to fill out the login status variables (for login/logout display)
    loginstatus = get_login_status()

    return render_template('privacy.html', 
                           loginstat=loginstatus,
                           pagetitle=app.config['APP_DISPLAY_NAME'],
                           returnurl=url_for('index'))

def load_app_client():
    return globus_sdk.ConfidentialAppAuthClient(
        app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])

def get_login_status():
    # This function returns a dictionary containing login information for the current session.
    # It is used to populate the login section of the UI.
    loginstat = dict()
    if not session.get('is_authenticated'):
         # prepare an empty status
         loginstat["status"] = False
         loginstat["loginlink"] = url_for('login')
         loginstat["logoutlink"] = ''
         loginstat["fullname"] = ''
         loginstat["identity"] = ''
    else:
         # User is logged in
         loginstat["status"] = True
         loginstat["loginlink"] = ''
         loginstat["logoutlink"] = url_for('logout', _external=True)
         loginstat["fullname"] = str(session.get('fullname'))
         loginstat["identity"] = str(session.get('identity'))
    return loginstat

def get_auth_events(introspectdata,oidcinfo):
    try:
        authns=introspectdata['session_info']['authentications']
    except:
        # There isn't a proper session_info entry in the token introspection results.
        return "Who let you in here?"
    if len(authns)<1:
        # The user didn't have to authenticate because there was an open session from another application.
        return "You didn't have to authenticate when you logged in."

    # There are authentication events!
    timenow = time.time()
    auth_events = ''
    first = True
    for authid,authdata in authns.items():
        # How long has it been since this event?
        duration = int((timenow-authdata['auth_time'])/60)
        # Look up the IdP in the identity_set from the oidcinfo structure.
        idp = '(unknown)'
        for id in oidcinfo.data['identity_set']:
            if (id['identity_provider'] == authdata['idp']):
                 idp = id['identity_provider_display_name']
        auth_events += 'You authenticated {} minutes ago with {}. '.format(duration,idp)
    return auth_events

# actually run the app if this is called as a script
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True,ssl_context=('./keys/server.crt', './keys/server.key'))

