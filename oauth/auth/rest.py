import kbr.tornado   as tornado


#!/usr/bin/env python3

''' REST API for auth'''

import argparse
import requests
import uuid

import kbr.log_utils as logger

import kbr.tornado   as tornado

import oauth.auth.facade as auth_db
import oauth.oauth2 as oauth2


# set by the init function:
db = None
introspection_url = None
client_id = None
client_secret = None

def introspection(token:str) -> dict:

#    print( f"TOKEN:: '{token}'" )
    url = f"{introspection_url}/{token}/"
#    print(url)
    return oauth2.local_introspection(token, client_id, client_secret)

def user_profile(user_id) -> dict:

    user = db.user_profiles(idp_user_id=user_id)[0]
    user['acls'] = db.user_acls(user['id'])

    return user


tornado.introspection_func = introspection
tornado.userprofile_func = user_profile


### Nothing beyond here should be changed #########


class UserHandler( tornado.BaseHandler ):

    def get(self):
#        print('getting user')
        # access control is done by the access token in this case!
        access_token = self.access_token()
#        print( access_token)
        token_data = introspection( access_token )
#        print( token_data )
        if 'active' not in token_data or token_data['active'] is not True:
            self.send_response_401( data="Token not active" )

        user_id = token_data[ 'data' ]['user_id']

        user_info = db.user_profiles( idp_user_id=user_id )
#        print(user_info)
        if user_info is None or user_info == []:
            self.send_response_404()
        user_info = user_info[0]

        user_info[ 'acls'] = db.user_acls( user_info['id'] )
        db.user_profile_update_login_date(user_info['id'])
        self.send_response(data=user_info)


    def options(self):
        self.allow_options()


class UserProfileDetailHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return("/admin/acl")
#        return("/admin/user_profile/[id]")

    def get(self, id:str):
        self.canRead(self.endpoint())

        user_profile  = db.user_profile(id=id)
        if user_profile is None:
            self.send_response_404()

        return self.send_response( data=user_profile)

    def patch(self, id:str):
        self.canUpdate(self.endpoint())
        user_profile = db.user_profile(id=id)
        if user_profile is None:
            self.send_response_404()

        values = self.post_values()
        # Check and change here!
        self.valid_arguments(values, ['id', 'idp_user_id', 'email', 'username', 'superuser', 'create_date', 'last_login'])
        values['id'] = id

        db.user_profile_update(**values)
        return self.send_response_200( )

    def delete(self, id:str):
        self.canDelete(self.endpoint())
        try:
            db.user_profile_delete( id=id )
            return self.send_response_200()
        except:
            return self.send_response_400()

    def options(self, id:str):
        self.allow_options()


class UserProfilesListHandler( tornado.BaseHandler):
    def endpoint(self):
        return("/admin/acl")
#        return "/admin/user_profiles/"

    def post(self):
        self.canCreate(self.endpoint())
        values = self.post_values()
        # check and change here
        self.require_arguments(values, ['idp_user_id', 'superuser'])
        self.valid_arguments(values, ['id', 'idp_user_id', 'email', 'username', 'superuser', 'create_date', 'last_login'])
        try:
            db.user_profile_create(**values)
            self.send_response_200()
        except Exception as e:
            logger.error(f"Request export tracking error {e}")
            self.send_response_404()

    def options(self):
        self.allow_options()

    def get(self):
        self.canRead(self.endpoint())
        filter = self.arguments()
        # check and change here
        self.valid_arguments(filter, ['id', 'idp_user_id', 'email', 'username', 'superuser', 'create_date', 'last_login'])
        profiles = db.user_profiles( **filter )
        for profile in profiles:
            user_roles = db.user_roles(user_profile_id=profile['id'])
            profile['roles'] = user_roles
        return self.send_response( profiles )


class UserRoleDetailHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return("/admin/acl")
#        return("/admin/user_role/[id]")

    def get(self, id:str):
        self.canRead(self.endpoint())
        user_role  = db.user_role(id=id)
        if user_role is None:
            self.send_response_404()

        return self.send_response( data=user_role)

    def patch(self, id:str):
        self.canUpdate(self.endpoint())
        user_role = db.user_role(id=id)
        if user_role is None:
            self.send_response_404()

        values = self.post_values()
        # Check and change here!
        self.valid_arguments(values, ['id', 'user_profile_id', 'role_id'])
        values['id'] = id

        db.user_role_update(**values)
        return self.send_response_200( )

    def delete(self, id:str):
        self.canDelete(self.endpoint())
        try:
            db.user_role_delete( id=id )
            return self.send_response_200()
        except:
            return self.send_response_400()

    def options(self, id:str):
        self.allow_options()


class UserRolesListHandler( tornado.BaseHandler):
    def endpoint(self):
        return("/admin/acl")
#        return "/admin/user_roles/"

    def post(self):
        self.canCreate(self.endpoint())
        values = self.post_values()
        print( values)

        if not isinstance(values, list):
            print('Not a list?')
            self.send_response_400()

        for value in values:
            self.require_arguments(value, ['user_profile_id', 'role_id'])
            self.valid_arguments(value, ['id', 'user_profile_id', 'role_id'])
            try:
                if value.get('id', False):                    
                    db.user_role_update(**value)
                else:
                    db.user_role_create(**value)

            except Exception as e:
                logger.error(f"Request export tracking error {e}")
                self.send_response_404()

        self.send_response_200()

    def options(self, id:str=None):
        self.allow_options()

    def get(self):
        self.canRead(self.endpoint())
        filter = self.arguments()

        # check and change here
        self.valid_arguments(filter, ['id', 'user_profile_id', 'role_id'])
        return self.send_response( db.user_roles( **filter ))


    def delete(self, user_role_id:str):
        self.canDelete(self.endpoint())
        try:
            db.user_role_delete_by_user_id( id=user_role_id )
            return self.send_response_200()
        except Exception as e:
            print( e )
            return self.send_response_400()


class RoleDetailHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return("/admin/acl")
#        return("/admin/role/[id]")

    def get(self, id:str):
        self.canRead(self.endpoint())
        role  = db.role(id=id)
        if role is None:
            self.send_response_404()

        return self.send_response( data=role)

    def patch(self, id:str):
        self.canUpdate(self.endpoint())
        role = db.role(id=id)
        if role is None:
            self.send_response_404()

        values = self.post_values()
        # Check and change here!
        self.valid_arguments(values, ['id', 'name'])
        values['id'] = id

        db.role_update(**values)
        return self.send_response_200( )

    def delete(self, id:str):
        self.canDelete(self.endpoint())
        try:
            db.role_delete( id=id )
            return self.send_response_200()
        except:
            return self.send_response_400()

    def options(self, id:str):
        self.allow_options()


class RolesListHandler( tornado.BaseHandler):
    def endpoint(self):
        return("/admin/acl")
#        return "/admin/roles/"

    def post(self):
        self.canCreate(self.endpoint())
        values = self.post_values()
        # check and change here
        self.require_arguments(values, ['name'])
        self.valid_arguments(values, ['id', 'name'])
        try:
            db.role_create(**values)
            self.send_response_200()
        except Exception as e:
            logger.error(f"Request export tracking error {e}")
            self.send_response_404()

    def options(self):
        self.allow_options()

    def get(self):
        self.canRead(self.endpoint())
        filter = self.arguments()
        # check and change here
        self.valid_arguments(filter, ['id', 'name'])
        roles = db.roles( **filter )
        for role in roles:
            acl_roles = db.acl_roles(role_id=role['id'])
            role['acls'] = acl_roles

        return self.send_response( roles )


class AclDetailHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return("/admin/acl")
#        return("/admin/acl/[id]")

    def get(self, id:str):
        self.canRead(self.endpoint())
        acl  = db.acl(id=id)
        if acl is None:
            self.send_response_404()

        return self.send_response( data=acl)

    def patch(self, id:str):
        self.canUpdate(self.endpoint())
        acl = db.acl(id=id)
        if acl is None:
            self.send_response_404()

        values = self.post_values()
        # Check and change here!
        self.valid_arguments(values, ['id', 'endpoint', 'can_create', 'can_read', 'can_update', 'can_delete'])
        values['id'] = id

        db.acl_update(**values)
        return self.send_response_200( )

    def delete(self, id:str):
        self.canDelete(self.endpoint())

        try:
            db.acl_delete( id=id )
            return self.send_response_200()
        except:
            return self.send_response_400()

    def options(self, id:str):
        self.allow_options()


class AclsListHandler( tornado.BaseHandler):
    def endpoint(self):
        return("/admin/acl")
#       return "/admin/acls/"

    def post(self):
        self.canCreate(self.endpoint())
        values = self.post_values()
        # check and change here
        self.require_arguments(values, ['endpoint'])
        self.valid_arguments(values, ['id', 'endpoint', 'can_create', 'can_read', 'can_update', 'can_delete'])
        try:
            db.acl_create(**values)
            self.send_response_200()
        except Exception as e:
            logger.error(f"Request export tracking error {e}")
            self.send_response_404()

    def options(self):
        self.allow_options()

    def get(self):
        self.canRead(self.endpoint())
        filter = self.arguments()
        # check and change here
        self.valid_arguments(filter, ['id', 'endpoint', 'can_create', 'can_read', 'can_update', 'can_delete'])
        return self.send_response( db.acls( **filter ))


class AclRoleDetailHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return("/admin/acl")
#        return("/admin/acl_role/[id]")

    def get(self, id:str):
        self.canRead(self.endpoint())
        acl_role  = db.acl_role(id=id)
        if acl_role is None:
            self.send_response_404()

        return self.send_response( data=acl_role)

    def patch(self, id:str):
        self.canUpdate(self.endpoint())
        acl_role = db.acl_role(id=id)
        if acl_role is None:
            self.send_response_404()

        values = self.post_values()
        # Check and change here!
        self.valid_arguments(values, ['id', 'acl_id', 'role_id'])
        values['id'] = id

        db.acl_role_update(**values)
        return self.send_response_200( )

    def delete(self, id:str):
        self.canDelete(self.endpoint())
        try:
            db.acl_role_delete( id=id )
            return self.send_response_200()
        except:
            return self.send_response_400()

    def options(self, id:str):
        self.allow_options()


class AclRolesListHandler( tornado.BaseHandler):
    def endpoint(self):
        return("/admin/acl")
#        return "/admin/acl_roles/"

    def post(self):
        self.canCreate(self.endpoint())
        values = self.post_values()
        print( values)

        if not isinstance(values, list):
            print('Not a list?')
            self.send_response_400()

        for value in values:
            self.require_arguments(value, ['acl_id', 'role_id'])
            self.valid_arguments(value, ['id', 'acl_id', 'role_id'])
            try:
                if value.get('id', False):                    
                    db.acl_role_update(**value)
                else:
                    db.acl_role_create(**value)

            except Exception as e:
                logger.error(f"Request export tracking error {e}")
                self.send_response_404()

        self.send_response_200()


    def options(self, id=None):
        self.allow_options()

    def get(self):
        self.canRead(self.endpoint())
        filter = self.arguments()
        # check and change here
        self.valid_arguments(filter, ['id', 'acl_id', 'role_id'])
        return self.send_response( db.acl_roles( **filter ))

    def delete(self, acl_id:str):
        self.canDelete(self.endpoint())
        try:
            db.acl_role_delete_by_acl_id( id=acl_id )
            return self.send_response_200()
        except Exception as e:
            print( e )
            return self.send_response_400()


def init(db_uri:str, intro_url:str=None, clnt_id:str=None, clnt_secret:str=None) -> list:

    global db, introspection_url, client_id, client_secret
    db = auth_db.DB()
    db.connect(db_uri )

    introspection_url = intro_url
    client_id = clnt_id
    client_secret = clnt_secret

    urls = [
            (r'/admin/user-profile/(\w+)/?$',  UserProfileDetailHandler),
            (r'/admin/user-profiles/?$',       UserProfilesListHandler),    
            (r'/admin/user-role/(\w+)/?$',     UserRoleDetailHandler),
            (r'/admin/user-roles/(\w+)/?$',     UserRolesListHandler),
            (r'/admin/user-roles/?$',          UserRolesListHandler),    
            (r'/admin/role/(\w+)/?$',         RoleDetailHandler),
            (r'/admin/roles/?$',              RolesListHandler),    
            (r'/admin/acl/(\w+)/?$',          AclDetailHandler),
            (r'/admin/acls/?$',               AclsListHandler),    
            (r'/admin/acl-role/(\w+)/?$',      AclRoleDetailHandler),
            (r'/admin/acl-roles/(\w+)/?$',     AclRolesListHandler),
            (r'/admin/acl-roles/?$',           AclRolesListHandler),

            (r'/me/?$', UserHandler),

            ]


    tornado.development()

    return urls
