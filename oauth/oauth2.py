#!/usr/bin/env python3
"""

 Kim Brugger
"""

from email.policy import default
from glob import glob
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

from google.auth import jwt
import requests

google_pem_certs = 'https://www.googleapis.com/oauth2/v1/certs'
certs = {}

import kbr.file_utils as file_utils
import kbr.password_utils as password_utils

import oauth.facade as auth_db
import kbr.tornado as tornado

client_store = ClientStore()
token_store = TokenStore()
db = None

acls = {}

def decode_jwt(response) -> dict:
    global certs

    try:
        user_info = jwt.decode(response, certs=certs)
    except ValueError:
        certs = requests.get( google_pem_certs).json()

        try:
            user_info = jwt.decode(response, certs=certs)
        except:
            raise RuntimeError

    return user_info



def local_introspection(token:str, client_id:str, client_secret:str) -> dict:
    global token_store

    try:
#        print('local introspection')
        token = token_store.fetch_by_token( token )
        client = client_store.fetch_by_client_id(client_id)

        if client_id != token.client_id:
            raise AssertionError('wrong client_id')

        if client.secret != client_secret:
            raise AssertionError('wrong client_secret')

        return {'success':True, 'active': True, 'data': token.data}
    except Exception as e:
        import traceback
        traceback.print_exc()

#        print( e )
        print("Token not found")
        return {'success': False}





class ImplicitSiteAdapter(ImplicitGrantSiteAdapter):


    def render_auth_page(self, request, response, environ, scopes, client):

        client_id      = tornado.url_unescape( request.get_param('client_id') )
        redirect_uri   = tornado.url_unescape( request.get_param('redirect_uri') )
        scope          = tornado.url_unescape( request.get_param('scope', default=None) )
        failed_message = environ.get('failed_message','')
        redirect_uri_encoded = tornado.url_escape( request.get_param('redirect_uri', default=None), plus=False )
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
        email = request.get_param("email")
        password = request.get_param("password")

        third_party = request.get_param('third_party', default=None)
#        print( third_party)

        if third_party == 'google':            
            response = request.get_param('response', None)

            try:
                user_info = decode_jwt(response)
#                print( user_info )
                environ[ 'failed_message' ] = f'Unknown google user: {user_info["email"]}'
                idp_user = db.idp_users( email=user_info['email'] )[0]

                db.idp_user_update_login_date(idp_user['id'])
                return {'user_id': idp_user['id'] }
            except Exception as e:
                environ[ 'failed_message' ] = f'Unknown google user or invalid jwt'
                print( e )
                raise UserNotAuthenticated

        elif email and password:

            idp_user = db.idp_users( email=email )
#            print(idp_user)
            if idp_user == [] or idp_user is None:
                environ[ 'failed_message' ] = 'Incorrect email and/or password'
                raise UserNotAuthenticated

            idp_user = idp_user[0]
            if password_utils.check_password(idp_user[ 'password'], password):
                return {'user_id':idp_user[ 'id' ] }
            else:
                environ[ 'failed_message' ] = 'Incorrect email and/or password'
                raise UserNotAuthenticated   

        raise UserNotAuthenticated

class ResetHandler( tornado.BaseHandler ):

    def get(self):

        args = self.arguments()
        username = args.get('username', None)
        if username is not None:
            #send email
            self.render('reset_email_sent.html')
        else:
            self.render("reset.html")



class RegisterHandler( tornado.BaseHandler ):

    def get(self):
        args = self.arguments()

        username = args.get("username", '')
        email    = args.get("email", '')
        password = args.get("password", '')


        redirect_uri   = tornado.url_unescape( args.get('redirect_uri',None) )
        redirect_uri = tornado.url_escape( redirect_uri, plus=False )
        client_id    = args.get("client_id", '')
        scope        = args.get("scope", '')


        third_party = args.get('third_party', None)
        failed_message = ''

        if args == {} and not third_party:
            self.render("register.html", failed_message='', username=username, email=email, redirect_uri=redirect_uri, client_id=client_id, scope=scope)
            return

        if third_party == 'google':            
            response = args.get('response', None)

            try:
                user_info = decode_jwt(response)
                username = user_info['name']
                email    = user_info['email']
                password =  ':'

            except:
                failed_message = f'Failed google user login'

        
        # This is not very nice nor elegant
        if username == '' and email != '' and password != '':
            failed_message = 'Missing username'

        if email == '' and username != '' and password != '':
            failed_message = f'Missing email {email}/{username}'

        if password == '' and username != '' and email != '':
            failed_message = f'Missing password {email}/{username}'        


        if '' not in [username, email] and password is None :
            failed_message = f'Missing password {failed_message}'

        if username != '' and failed_message == '':
            db_user = db.idp_users(email=email)

            if db_user:
                failed_message = f"User with email '{email}' is already registered. If you have forgotten your email please click the reset link at the top."
            else:
                db.idp_user_create(email, password, username)
                db_user = db.idp_users(email=email)

            # If a redirect from a registration move to login page
            if failed_message == '' and redirect_uri != '':
                return self.redirect(f"/authorize?response_type=token&client_id={client_id}&redirect_uri={redirect_uri}")
            elif failed_message != '':
                return self.render("register_success.html")

        self.render("register.html", failed_message=failed_message, username=username, email=email, redirect_uri=redirect_uri, client_id=client_id, scope=scope)



class TosHandler( tornado.BaseHandler ):

    def get(self):
        self.render("tos.html")


class  PrivacyHandler( tornado.BaseHandler ):

    def get(self):
        self.render("privacypolicy.html")

class IntrospectionHandler( tornado.BaseHandler ):

    def get(self, token:str=None):
        global token_store
        try:
            args = self.arguments()
            client_id = args.get('client_id', None)
            client_secret = args.get('client_secret', None)
#            print(f"Args: {client_id}/{client_secret}")

            token = token_store.fetch_by_token( token )
#            pp.pprint( token )

#            pp.pprint( token.client_id )
#            pp.pprint( token.grant_type )
#            pp.pprint( token.token )
#            pp.pprint( token.data )
#            pp.pprint( token.expires_at )
#            pp.pprint( token.refresh_token )
#            pp.pprint( token.refresh_expires_at )
#            pp.pprint( token.scopes )
#            pp.pprint( token.user_id )

            if client_id != token.client_id:
                raise AssertionError('wrong client_id')

            client = client_store.fetch_by_client_id(client_id)
            if client.secret != client_secret:
                raise AssertionError('wrong client_secret')

#            pp.pprint( token )
            user = db.idp_user(id = token.user_id)
            del user['password']
            del user['last_login']

            self.send_response({'success':True, 'active': True, 'data': user})
            return
        except:
            print("Token not found")
            self.send_response_401({'success': False})
            return


    def post(self, token:str=None):
        global token_store
        try:
            values = self.post_values()
            client_id = values.get('client_id', None)
            client_secret = values.get('client_secret', None)
#            print(f"Args: {client_id}/{client_secret}")

            token = token_store.fetch_by_token( token )
#            pp.pprint( token )
#
#            pp.pprint( token.client_id )
#            pp.pprint( token.grant_type )
#            pp.pprint( token.token )
#            pp.pprint( token.data )
#            pp.pprint( token.expires_at )
#            pp.pprint( token.refresh_token )
#            pp.pprint( token.refresh_expires_at )
#            pp.pprint( token.scopes )
#            pp.pprint( token.user_id )

            client = client_store.fetch_by_client_id(client_id)
#            print( client )
            if client_id != token.client_id:
                raise AssertionError('wrong client_id')

            if client.secret != client_secret:
                raise AssertionError('wrong client_secret')

            user_id = token.data['user_id']
            #print("Userid:", user_id)

            user = db.idp_user(id = user_id)
            del user['password']
            del user['last_login']
            user['user_id'] = user['id']
            del user['id']

            #print(user)

            self.send_response({'success':True, 'active': True, 'data': user})
            return
        except Exception as e:
            import traceback
            traceback.print_exc()

            #print( e )
            print("Token not found")
            self.send_response_401({'success': False})
            return



def introspection(token:str) -> dict:

    global token_store
    try:
        response = token_store.fetch_by_token( token )
        return {'success': True, 'active': True, 'data': response.data}
    except Exception as e:
        return {'success': False, "mgs": "{}: {}".format( e.__class__.__name__, e ) }

class IdpUserDetailHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return "/idp-users/"
        return("/idp_user/[id]")

    def get(self, id:str):
        self.canRead(self.endpoint())

        idp_user  = db.idp_user(id=id)
        if idp_user is None:
            self.send_response_404()

        return self.send_response( data=idp_user)

    def patch(self, id:str):
        self.canUpdate(self.endpoint())

        idp_user = db.idp_user(id=id)
        if idp_user is None:
            self.send_response_404()

        values = self.post_values()
        # Check and change here!
        self.valid_arguments(values, ['id', 'email', 'password', 'username', 'create_date', 'last_login'])
        values['id'] = id

        values['password'] = password_utils.hash_password(values['password'])

        db.idp_user_update(**values)
        return self.send_response_200( )

    def delete(self, id:str):
        self.canDelete(self.endpoint())
        try:
            db.idp_user_delete( id=id )
            return self.send_response_200()
        except:
            return self.send_response_400()

    def options(self, id:str):
        self.allow_options()


class IdpUsersListHandler( tornado.BaseHandler):
    def endpoint(self):
        return "/idp-users/"

    def post(self):
        self.canCreate(self.endpoint())
        values = self.post_values()
        # check and change here
        self.require_arguments(values, ['email', 'password', 'username'])
        self.valid_arguments(values, ['id', 'email', 'password', 'username', 'active', 'create_date', 'last_login'])
        try:
            db.idp_user_create(**values)
            self.send_response_200()
        except Exception as e:
            print(f"User update error: {e}")
            self.send_response_404()

    def options(self):
        self.allow_options()

    def get(self):
        self.canRead(self.endpoint())
        filter = self.arguments()
        # check and change here
        self.valid_arguments(filter, ['id', 'email', 'password', 'username', 'active', 'create_date', 'last_login'])
        return self.send_response( db.idp_users( **filter ))



def init( auth_database:str, clients:list ) -> list:

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

    tornado.development()

    urls = [
        #/authorize?client_id=...&redirect_uri=...&response_type=token
        url(provider.authorize_path, OAuth2Handler, dict(provider=provider)),
        url(r'/introspect/(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})/?$', IntrospectionHandler),
        url(r'/reset/?$', ResetHandler),
        url(r'/privacy/?$', PrivacyHandler),
        url(r'/tos/?$', TosHandler),
        url(r'/register/?$', RegisterHandler),
        url(r'/api/idp-user/(\w+)/?$',    IdpUserDetailHandler),
        url(r'/api/idp-users/?$',         IdpUsersListHandler),    


    ]

    return urls
