#!/usr/bin/env python3
"""

 Kim Brugger
"""

from email.policy import default
import logging
import pprint
from urllib import request
pp = pprint.PrettyPrinter(indent=4)

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.web import ImplicitGrantSiteAdapter
from oauth2.grant import ImplicitGrant
from oauth2.tokengenerator import Uuid4
from oauth2.store.memory import ClientStore, TokenStore
from oauth2.web.tornado import OAuth2Handler
from tornado.web import url


import kbr.file_utils as file_utils
import kbr.password_utils as password_utils

import oauth.auth_db as auth_db
import kbr.tornado as tornado

client_store = ClientStore()
token_store = TokenStore()
db = None

acls = {}

class ImplicitSiteAdapter(ImplicitGrantSiteAdapter):


    def render_auth_page(self, request, response, environ, scopes, client):

        client_id      = tornado.url_unescape( request.get_param('client_id') )
        redirect_uri   = tornado.url_unescape( request.get_param('redirect_uri') )
        scope          = tornado.url_unescape( request.get_param('scope', default=None) )
        failed_message = environ.get('failed_message','')
        redirect_uri_encoded = "http%3A%2F%2Fblood.bruggercorp.com%2F%23login"

        # Readin template file and replace values with the values extracted above.
        # ! Should throw an error of something is missing
        login = file_utils.read( "templates/login.html")

        response.body = login.format( redirect_uri=redirect_uri,
                                      redirect_uri_encoded=redirect_uri_encoded,  
                                      client_id=client_id,
                                      scope=scope,
                                      failed_message=failed_message)


        return response

    def user_has_denied_access(self, request):
        # ignoring this for now, so just return a false
        return False

    def authenticate(self, request, environ, scopes, client):
        username = request.get_param("username")
        password = request.get_param("password")

        third_party = request.get_param('third_party', default=None)
        print( third_party)

        if third_party == 'telegram':
            id = request.get_param('id', default=None)
            first_name = request.get_param('first_name', None)
            last_name  = request.get_param('last_name', None)
            print("TELEGRAM", third_party, first_name, last_name, id)

        if username and password:

            #print(username, password)

            return {'user_id': username }

            idp_user = db.idp_user_get( username )
            print( idp_user )
            if idp_user is None or not password_utils.check_password(idp_user[ 'password'], password):
                environ[ 'failed_message' ] = 'Incorrect username and/or password'
            else:
                user_profile = db.user_profile_get( idp_user_id=idp_user[ 'id'])
                return {'user_id':user_profile[ 'id' ] }

        raise UserNotAuthenticated

class UserHandler( tornado.BaseHandler ):

    def get(self):

        access_token = self.access_token()
        token_data = introspection( access_token )
        if 'active' not in token_data or token_data['active'] is not True:
            self.send_response_401( data="Token not active" )

        user_id = token_data[ 'data' ]['user_id']

        user_info = db.user_profile_get( id=user_id )
        if user_info is None:
            self.send_response_404()

        user_info[ 'acls'] = db.get_acls( user_id )
        pp.pprint( user_info )
        self.send_response(data=user_info)

class IntrospectionHandler( tornado.BaseHandler ):

    def get(self, token:str=None):
        global token_store
        try:
            token = token_store.fetch_by_token( token )
            pp.pprint( token )

            pp.pprint( token.client_id )
            pp.pprint( token.grant_type )
            pp.pprint( token.token )
            pp.pprint( token.data )
            pp.pprint( token.expires_at )
            pp.pprint( token.refresh_token )
            pp.pprint( token.refresh_expires_at )
            pp.pprint( token.scopes )
            pp.pprint( token.user_id )

            self.send_response({'success':True, 'active': True, 'data': token.data})
            return
        except:
            print("Token not found")
            self.send_response_401({'success': False})
            return


def introspection(token:str) -> {}:

  #  return {'success': True, 'active': True, 'data': {}}

    global token_store
    try:
        response = token_store.fetch_by_token( token )
        return {'success': True, 'active': True, 'data': response.data}
    except Exception as e:
        return {'success': False, "mgs": "{}: {}".format( e.__class__.__name__, e ) }

def init( auth_database:str, clients:[] ) -> []:


    global db
    db = auth_db.DB()
    db.connect( auth_database )

    global token_store
    global client_store


    for client in clients:
        print("Configuring client: {}".format(client))

        client = clients[ client ]

        client_store.add_client(client_id=client.client_id, client_secret=client.client_secret,
                                redirect_uris=client.redirect_uris )

    provider = Provider(
        access_token_store = token_store,
        auth_code_store    = token_store,
        client_store       = client_store,
        token_generator    = Uuid4())

    provider.add_grant(ImplicitGrant(site_adapter=ImplicitSiteAdapter()))

    print("Auth url: {}".format( provider.authorize_path ))

    urls = [
        url(provider.authorize_path, OAuth2Handler, dict(provider=provider)),
 #       url(r'/me/(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})/?$', UserHandler),
        url(r'/introspect/(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})/?$', IntrospectionHandler),
        url(r'/me/?$', UserHandler),
    ]

    return urls
