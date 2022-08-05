
import oauth.auth.db as db

class DB(db.DB):

    def user_role_delete_by_user_id(self, id) -> None:
        q = f"DELETE FROM user_role WHERE user_profile_id = '{id}'"
        self._db.do( q )


    def acl_role_delete_by_acl_id(self, id) -> None:
        q = f"DELETE FROM acl_role WHERE acl_id = '{id}'"
        self._db.do( q )


    def user_profile_update_login_date(self, id:str) -> dict:
        q = f"update user_profile set last_login=now() where id = '{id}'"
        self._db.do(q)


    def user_acls(self, user_profile_id:str) -> list:

        roles = self.user_roles( user_profile_id=user_profile_id )
        acls = {}
        for role in roles:
            acl_roles = self.acl_roles( role_id=role['role_id'])

            for acl_role in acl_roles:
                acl_id = acl_role[ 'acl_id' ]
                acl = self.acl(id=acl_id)
                endpoint = acl[ 'endpoint' ]

                if endpoint not in acls:
                    acls[ endpoint ] = {'can_create': acl['can_create'],
                                        'can_read':acl['can_read'],
                                        'can_update':acl['can_update'],
                                        'can_delete':acl['can_delete'],
                                        }
                else:
                    acls[endpoint]['can_create'] = acls[endpoint]['can_create'] or acl['can_create']
                    acls[endpoint]['can_read']   = acls[endpoint]['can_read'] or acl['can_read']
                    acls[endpoint]['can_update'] = acls[endpoint]['can_update'] or acl['can_update']
                    acls[endpoint]['can_delete'] = acls[endpoint]['can_delete'] or acl['can_delete']


        return acls


