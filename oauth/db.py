import kbr.db_utils as db

class DB(object):


    def connect(self, url:str) -> None:
        self._db = db.DB( url )

    def disconnect(self) -> None:
        if self._db is not None:
            self._db.close()



#################### USER ####################


    def idp_user_create(self, email:str, password:str, username:str=None) -> {}:

#        if self.idp_user_get( email=email ):
            #print("{} already exists in the database".format( username ))
#            return self.idp_user_get( email=email )

        entry = {'email': email,
                 'password': password,
                 'username': username}

        return self._db.add_unique('idp_user', entry, 'email')


    def idp_user_get(self, email:str) -> {}:
        return self._db.get_single('idp_user', email=email)

    def idp_users(self) -> {}:
        return self._db.get('idp_users')


    def idp_user_update(self, id:str, **values) -> {}:

        entry = {}
        for value in values:
            if value in ['email', 'password', 'username']:
                entry[ value ] = values[ value ]


        if entry == {}:
            return None

        entry['id'] = id
        print( entry )
        return self._db.update('idp_user', entry, {'id':id})


    def idp_user_delete(self, id:str) -> {}:
        return  self._db.delete('idp_user', id=id)


    def user_profile_create(self, email:str, idp_user_id:str, idp_source:int=1, username:str=None, superuser:bool=False) -> {}:
        entry = { 'username': username,
                  'idp_user_id': idp_user_id,
                  'idp_source': idp_source,
                  'superuser': superuser,
                  'email': email
                  }

        user = self._db.add_unique('user_profile', entry, 'idp_user_id')
        # Usernames are unique so either none or a list of length one
        return user


    def user_profiles(self) -> {}:
        return self._db.get('user_profile')


    def user_profile_get(self, **values) -> {}:
        #print( values )
        fields = ['id', 'idp_user_id','email']
        for value in values:
            if value in fields:
                return self._db.get_single('user_profile', **{value:values[ value ]})

        return None


    def user_profile_update(self, id:str, **values) -> {}:

        entry = {'id': id}
        for value in values:
            if value in ['email', 'username', 'superuser']:
                entry[ value ] = values[ value ]

        return self._db.update('user_profile', entry, {'id':id})


    def user_profile_delete(self, id:str) -> {}:

        user_groups = self.user_groups(user_profile_id=id)
        for user_group in user_groups:
                self.user_group_delete(user_group['id'])

        return  self._db.delete('user_profile', id=id)


    def get_acls(self, user_profile_id:str) -> []:

        groups = self.user_groups( user_profile_id=user_profile_id )
        acls = {}
        for group in groups:
            group_acls = self.group_acls( groups_id=group['groups_id'])

            for group_acl in group_acls:
                acl_id = group_acl[ 'acl_id' ]
                acl = self.acl_get(id=acl_id)
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


#################### GROUP ####################

    def groups_create(self, name:str) -> None:
        return self._db.add_unique('groups', {'name': name},'name')

    def groups_get(self, name:str=None, id:str=None) -> None:
        group = self._db.get_single('groups', name=name, id=id)
        return group

    def groups(self) -> None:
        return self._db.get('groups')

    def groups_delete(self, uuid:str) -> None:
        # delete all acls that referes to this group:

        group = self.groups_get( uuid )
        acl_groups = self.group_acls(groups_id=uuid)
        for acl_group in acl_groups:
            self.group_acl_delete( acl_group['id'])

        user_groups = self.user_groups(groups_id=uuid)
        for user_group in user_groups:
            self.user_group_delete(user_group['id'])


        return self._db.delete('groups', uuid)



    def add_user_to_group(self, user_profile_id:str, groups_id:str) -> {}:
        entry = {'user_profile_id' : user_profile_id,
                 'groups_id'   : groups_id}

        print( entry )

        self._db.add('user_group', entry)



    def add_group_to_acl(self, groups_id:str, acl_id:str) -> {}:
        entry = {'acl_id': acl_id,
                 'groups_id': groups_id}

        print( entry )

        self._db.add('acl_group', entry)


#    def get_user_info(self, idp_user_id:str) -> {}:

#        user = {}
#        user[ 'acls'] = []

#        user['profile'] = self.get_user_profile( auth_user_id )
#        auth_user_id = user['profile']['id']

#        user[ 'groups' ]  = self.auth_user_groups( auth_user_id )
#        for group in user[ 'groups' ]:
#            user[ 'acls'] += self.get_acls( group[ 'groups_id'])

#        return user


#################### auth_user_group ####################

    def user_group_add(self, groups_id:str, user_profile_id:str) -> None:
        return self._db.add('user_groups', {'user_profile_id': user_profile_id, 'groups_id':groups_id})

    def user_groups(self, groups_id:str=None, user_profile_id:str=None) -> {}:
        group_acls = self._db.get('user_groups', groups_id=groups_id, user_profile_id=user_profile_id)
        return group_acls

    def user_group_delete(self, id:str) -> None:
        print("Deleting ", id)
        return self._db.delete('user_groups', id=id)


#################### group_ACL ####################

    def acl_group_add(self, acl_id:str, groups_id:str) -> None:

        return self._db.add('acl_groups', {'groups_id': groups_id, 'acl_id':acl_id})

    def acl_group_remove(self, acl_groups_id:str) -> None:
        return self._db.delete('acl_groups', id=acl_groups_id)


    def group_acls(self, groups_id:str=None, acl_id:str=None) -> {}:
        group_acls = self._db.get('acl_groups', groups_id=groups_id, acl_id=acl_id)
        return group_acls

    def group_acl_delete(self, uuid:str) -> None:
        # delete all acls that referes to this group:

        return self._db.delete('acl_groups', id=uuid)


    #################### ACL ####################


    def acl_create(self, endpoint:str, can_create:bool=False, can_read:bool=False, can_update:bool=False, can_delete:bool=False):
        entry = { 'endpoint': endpoint,
                  'can_create': can_create,
                  'can_read': can_read,
                  'can_update': can_update,
                  'can_delete': can_delete}

        self._db.add('acl', entry)


    def acl_get(self, id:str=None, uri:str=None) -> {}:
        acl = self._db.get_single('acl', id=id, uri=uri)
        return acl

    def acls(self) -> None:
        return self._db.get('acl')

    def acl_delete(self, uuid:str) -> None:

        acl_groups = self.group_acls( acl_id=uuid )
        if acl_groups is not None:
            for acl_group in acl_groups:
                self.acl_group_remove( acl_group[ 'id'] )

        return self._db.delete('acl', uuid)



    def acl_update(self, id:str, **values) -> {}:

        entry = {'id': id}
        for value in values:
            if value in ['endpoint', 'can_create', 'can_read', 'can_update', 'can_delete']:
                entry[ value ] = values[ value ]

        return self._db.update('acl', entry, {'id':id})
