#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, url_for, session, redirect, request
import globus_sdk
import json

app = Flask(__name__)
app.config.from_pyfile('auth_example.conf')

@app.route('/')
def index():
    """
    This could be any page you like, rendered by Flask.
    For this simple example, it will either redirect you to login, or print
    a simple message.
    """
    if not session.get('is_authenticated'):
         # display all this information on the web page
         page = '<html>\n<head><title>Display Your Auth Data</title></head>\n\n'
         page = page + '<body>\n<p><b>You are not logged in.</b></p>\n\n'
         page = page + '<p>If you login, this page will show you what the Globus Auth API tells apps about you.</p>\n\n'
         page = page + '<p><a href="' + url_for('login') + '">Click here to login.</a></p>\n'
         page = page + '</body></html>'
         return(page)
         # return redirect(url_for('login'))
    logout_uri = url_for('logout', _external=True)

    # get the stored access token for the Auth API and use it 
    # to authorize stuff AS THE AUTHENTICATED USER
    auth_token = str(session.get('tokens')['auth.globus.org']['access_token'])
    ac = globus_sdk.AuthClient(authorizer=globus_sdk.AccessTokenAuthorizer(auth_token))

    # use Auth API to get more info about the authenticated user
    myids = ac.get_identities(ids=str(session.get('username')),include="identity_provider").data

    # use Auth API to get the standard OIDC userinfo fields (like any OIDC client)
    oidcinfo = ac.oauth2_userinfo()

    # get the stored OIDC id_token
    myoidc = session.get('id_token')

    # authenticate to Auth API AS AN APPLICATION and find out still more information
    cc = load_app_client()
    ir = cc.oauth2_token_introspect(auth_token,include='identities_set').data

    # display all this information on the web page
    page = '<html>\n<head><title>Display Your Auth Data</title></head>\n\n'
    page = page + '<body>\n<p><b>' + str(session.get('realname')) + ', you are logged in.</b></p>\n\n'
    page = page + '<p><b>Your local username is:</b> ' + str(session.get('username')) + '</p>\n\n'
    page = page + '<p><a href="'+logout_uri+'">Logout now.</a></p>\n\n'
    page = page + '<h2>Your OpenID Connect Data</h2>\n\n'
    page = page + '<p>The following data is what OpenID Connect (OIDC) applications see.</p>'
    page = page + '<p>OIDC\'s <b>oauth2_userinfo()</b> call says:</p>\n\n'
    page = page + '<ul>\n<li>Your name is "' + oidcinfo["name"] + '".\n'
    page = page + '<li>Your email address is "' + oidcinfo["email"] + '".\n'
    page = page + '<li>Your preferred_username is "' + oidcinfo["preferred_username"] + '".\n'
    page = page + '<li>Your effective ID is "' + oidcinfo["sub"] + '".\n</ul>\n\n'
    page = page + '<p>Your OIDC <b>id_token</b> looks like this:</p>\n<pre>' + json.dumps(myoidc,indent=3) + '</pre>\n\n'
    page = page + '<p><b>oauth2_userinfo()</b> with the optional view_identity_set scope returns this:</p>\n\n'
    page = page + '<pre>' + json.dumps(oidcinfo.data,indent=3) + '</pre>\n\n'
    page = page + '<h2>Your Globus Data</h2>'
    page = page + '<p>The following data is available via the Globus Auth API.</p>'
    page = page + '<p><b>get_identities()</b> returns this:</p>\n'
    page = page + '<pre>' + json.dumps(myids,indent=3) + '</pre>\n\n'
    page = page + '<p><b>oauth2_token_introspect()</b> for your Auth API access token returns this:</p>\n'
    page = page + '<pre>' + json.dumps(ir,indent=3) + '</pre>\n\n'
    # We probably shouldn't display the token, but for debugging purposes, this is how you'd do it...
    # page = page + '<p>The tokens I received are:</p>\n<pre>' + json.dumps(session.get('tokens'),indent=3) + '</pre>\n\n'
    page = page + '</body></html>'
    return(page)

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
        ids = tokens_response.decode_id_token(auth_client)
        session.update(
                tokens=tokens_response.by_resource_server,
                id_token=ids,
                username=ids['sub'],
                realname=ids['name'],
                is_authenticated=True
                )
        return redirect(url_for('index'))

@app.route("/logout")
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    client = load_app_client()

    # Revoke the tokens with Globus Auth
    for token in (token_info['access_token']
                  for token_info in session['tokens'].values()):
        client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # the return redirection location to give to Globus AUth
    redirect_uri = url_for('index', _external=True)

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client={}'.format(app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(redirect_uri) +
        '&redirect_name=Display Your Auth Data')

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)

def load_app_client():
    return globus_sdk.ConfidentialAppAuthClient(
        app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])

# actually run the app if this is called as a script
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True,ssl_context=('./keys/server.crt', './keys/server.key'))

