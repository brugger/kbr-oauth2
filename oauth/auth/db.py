
import kbr.db_utils as db

class DB(object):

    def connect(self, url: str) -> None:
        self._db = db.DB(url)

    def disconnect(self) -> None:

        if self._db is not None:
            self._db.close()
##### user_profile #####

    def user_profile_create(self, idp_user_id:str, superuser:bool, **values) -> dict:

        values['idp_user_id'] = idp_user_id
        values['superuser'] = superuser

        p = self._db.add('user_profile', values)

        return self._db.get('user_profile', **values)


    def user_profile(self, id:str) -> dict:
        return self._db.get_by_id('user_profile', id)

    def user_profiles(self, **values) -> dict:
        return self._db.get('user_profile', **values)

    def user_profile_update(self, **values) -> dict:
        self._db.update('user_profile', values, {'id': values['id']})

    def user_profile_delete(self, id) -> None:
        self._db.delete('user_profile', id=id)

    def user_profile_purge(self) -> None:
        self._db.purge('user_profile')
##### user_role #####

    def user_role_create(self, user_profile_id:str, role_id:str, **values) -> dict:

        values['user_profile_id'] = user_profile_id
        values['role_id'] = role_id

        p = self._db.add('user_role', values)

        return self._db.get('user_role', **values)


    def user_role(self, id:str) -> dict:
        return self._db.get_by_id('user_role', id)

    def user_roles(self, **values) -> dict:
        return self._db.get('user_role', **values)

    def user_role_update(self, **values) -> dict:
        self._db.update('user_role', values, {'id': values['id']})

    def user_role_delete(self, id) -> None:
        self._db.delete('user_role', id=id)

    def user_role_purge(self) -> None:
        self._db.purge('user_role')
##### role #####

    def role_create(self, name:str, **values) -> dict:

        values['name'] = name

        p = self._db.add('role', values)

        return self._db.get('role', **values)


    def role_create_unique(self, name:str, **values) -> dict:

        values['name'] = name

        return self._db.add_unique('role', values, ['name'])


    def role(self, id:str) -> dict:
        return self._db.get_by_id('role', id)

    def roles(self, **values) -> dict:
        return self._db.get('role', **values)

    def role_update(self, **values) -> dict:
        self._db.update('role', values, {'id': values['id']})

    def role_delete(self, id) -> None:
        self._db.delete('role', id=id)

    def role_purge(self) -> None:
        self._db.purge('role')
##### acl #####

    def acl_create(self, endpoint:str, **values) -> dict:

        values['endpoint'] = endpoint

        p = self._db.add('acl', values)

        return self._db.get('acl', **values)


    def acl_create_unique(self, endpoint:str, **values) -> dict:

        values['endpoint'] = endpoint

        return self._db.add_unique('acl', values, ['endpoint'])


    def acl(self, id:str) -> dict:
        return self._db.get_by_id('acl', id)

    def acls(self, **values) -> dict:
        return self._db.get('acl', **values)

    def acl_update(self, **values) -> dict:
        self._db.update('acl', values, {'id': values['id']})

    def acl_delete(self, id) -> None:
        self._db.delete('acl', id=id)

    def acl_purge(self) -> None:
        self._db.purge('acl')
##### acl_role #####

    def acl_role_create(self, acl_id:str, role_id:str, **values) -> dict:

        values['acl_id'] = acl_id
        values['role_id'] = role_id

        p = self._db.add('acl_role', values)

        return self._db.get('acl_role', **values)


    def acl_role(self, id:str) -> dict:
        return self._db.get_by_id('acl_role', id)

    def acl_roles(self, **values) -> dict:
        return self._db.get('acl_role', **values)

    def acl_role_update(self, **values) -> dict:
        self._db.update('acl_role', values, {'id': values['id']})

    def acl_role_delete(self, id) -> None:
        self._db.delete('acl_role', id=id)

    def acl_role_purge(self) -> None:
        self._db.purge('acl_role')
