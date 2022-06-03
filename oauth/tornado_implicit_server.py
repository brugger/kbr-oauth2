#!/usr/bin/env python3
""" 
 
 
 
 Kim Brugger (14 Jun 2019), contact: kim.brugger@uib.nok
"""

import logging
import pprint
pp = pprint.PrettyPrinter(indent=4)
import tornado as tornado

import jwt

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.web import ImplicitGrantSiteAdapter
from oauth2.grant import ImplicitGrant
from oauth2.tokengenerator import Uuid4
from oauth2.store.memory import ClientStore, TokenStore
from oauth2.web.tornado import OAuth2Handler
from tornado.web import Application, url


import tornado_utils as tornado

logging.basicConfig(level=logging.DEBUG)


class JWTGenerator(object):
    """
    Base class of every token generator.
    """
    def __init__(self):
        """
        Create a new instance of a token generator.
        """
        default_livespan = 60*60 # one hour
        self.expires_in = {'authorization_code': default_livespan,
                           'implicit': default_livespan,
                           'password': default_livespan,
                           'refresh_token': default_livespan,
                           'client_credentials': default_livespan}
        self.refresh_expires_in = 0

    def create_access_token_data(self, grant_type):
        """
        Create data needed by an access token.

        :param grant_type:
        :type grant_type: str

        :return: A ``dict`` containing he ``access_token`` and the
                 ``token_type``. If the value of ``TokenGenerator.expires_in``
                 is larger than 0, a ``refresh_token`` will be generated too.
        :rtype: dict
        """
        if self.expires_in.get(grant_type, 0) > 0:
            result["refresh_token"] = self.generate()

            result["expires_in"] = self.expires_in[grant_type]

        result = {"access_token": self.generate(grant_type=grant_type), "token_type": "Bearer"}


            
        return result

    def generate(self, grant_type:str, iat:int, username:str, exp:str, ):
        """
        Implemented by generators extending this base class.

        :raises NotImplementedError:
        """

        payload = {'active': 'true',
                   'token_type': "Bearer",
                   'grant_type': grant_type,
                   'iat': iat
        }
        
        encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
        decoded = jwt.decode(encoded, 'secret', algorithms=['HS256'])
        
        raise NotImplementedError



client_store = ClientStore()
token_store = TokenStore()


class TestSiteAdapter(ImplicitGrantSiteAdapter):


    LOGIN_TEMPLATE = """<html>
    <body>
        <h1>Login</h1>
        <div style="color: red;">
          {failed_message}
        </div>
        <form method="GET" name="confirmation_form" action="/authorize">
            <div>
                Username (foo): <input name="username" type="text" value='foo'/>
            </div>
            <div>
                Password (bar): <input name="password" type="password" value='bar'/>
            </div>
            <div>
               client_id: <input type="text"  name="client_id" value="{client_id}">
            </div>
            <div>
              redirect_url: <input type="text"  name="redirect_uri" value="{redirect_uri}">
            </div>
            <div>
              scope: <input type="text" name="scopes" value="{scope}">
            </div>
            <div>
              response_type: <input type="text" name="response_type" value="token">
            </div>

            <div>
                <button id="btn1" name="submit" type="submit" value="submit">Submit</button>
                <button id="btn2" name="cancel" type="submit" value="cancel">Cancel</button>
            </div>
        </form>
    </body>
</html>"""

    
    def render_auth_page(self, request, response, environ, scopes, client):
#        print( "------------ render_auth_page ")
        print( "Main environ: ")
        print( environ )

        client_id      = tornado.url_unescape( request.get_param('client_id') )
        redirect_uri   = tornado.url_unescape( request.get_param('redirect_uri') )
        scope          = tornado.url_unescape( request.get_param('scope') )
        failed_message = environ.get('failed_message','')
        print( "Failed message:" +  failed_message )

        print(client_id)
        print(redirect_uri)
        print(scope)

        
        response.body = self.LOGIN_TEMPLATE.format( redirect_uri=redirect_uri,
                                                    client_id=client_id,
                                                    scope=scope,
                                                    failed_message=failed_message)

        return response

    def user_has_denied_access(self, request):
#        print( "------------ user_has_denied_access ")
        # if request.method == "GET":
        #     if request.get_param("logged_in") == 'True':
        #         print( "User have allowed access ... ")
        #         return True

        return False

    def authenticate(self, request, environ, scopes, client):
#        print( "-------------  authenticate")
#        print( "params: ", request.get_params() )
        username = request.get_param("username")

        password = request.get_param("password")
#        print( username == b"foo" )
#        print( password == b"bar" )

        if username == "foo" and password == "bar":
            #            print( 'Known user ..... ')
            print( token_store.access_tokens )
            print( token_store.auth_codes )
#            environ[ 'token_type' ] = 'JWT'
#            environ[ 'secret' ] = 'the-secret'


            return {'user_id':'1234'}

            return {'user':'good'}
            return ['logged_in', 'True']

        

        environ[ 'failed_message' ] = 'Login failed'
        
        raise UserNotAuthenticated


        
    

class IntrospectionHandler(tornado.BaseHandler):

    def get(self, token:str=None):
        global token_store
        print( "---------get w/ '{}'".format( token ))
        try:
            token = token_store.fetch_by_token( token )
#            pp.pprint( token )
#            print( token_store.access_tokens )
#            print( token_store.auth_codes )

#            print( token.client_id)
#            print( token.grant_type)
#            print( token.token)
            print( token.data)
#            print( token.expires_at)
#            print( token.refresh_token)
#            print( token.refresh_expires_at)
#            print( token.scopes )
            print( token.user_id )

            self.send_response({'active': True, 'data': token.data})
            return
        except:
            print("Token not found")
            self.send_response_401({'success': False})
            return


def run_auth_server():

    
    client_store.add_client(client_id="abc", client_secret="xyz",
                            redirect_uris=['http://localhost/vmail-frontend/#login'])

    global token_store
    
    provider = Provider(
        access_token_store=token_store,
        auth_code_store=token_store,
        client_store=client_store,
        token_generator=Uuid4())

    provider.add_grant(ImplicitGrant(site_adapter=TestSiteAdapter()))

    print( provider.authorize_path )

    
    urls = [
        url(provider.authorize_path, OAuth2Handler, dict(provider=provider)),
        url(r'/introspection/(\w+-\w+-\w+-\w+-\w+)/?$', IntrospectionHandler),
#        url(r'/validate/(\w+\.\w+\.\w+)/?$', IntrospectionHandler),
#        url(r'/userinfo/(\w+\.\w+\.\w+)/?$', UserHandler),
#        url(r'/introspection/(\w+\.\w+\.\w+)/?$', IntrospectionHandler),
#        url(r'/introspection/(\w+\.\w+\.\w+)/?$', IntrospectionHandler),
    ]

    print("Starting OAuth2 server on http://localhost:8080/...")
    tornado.run_app( urls, debug=True, port=8080 )



 
if __name__ == "__main__":
    run_auth_server()
