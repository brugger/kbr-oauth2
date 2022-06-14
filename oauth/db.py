
import kbr.db_utils as db

class DB(object):

    def connect(self, url: str) -> None:
        self._db = db.DB(url)

    def disconnect(self) -> None:

        if self._db is not None:
            self._db.close()
##### idp_user #####

    def idp_user_create(self, email:str, password:str, username:str, **values) -> dict:

        values['email'] = email
        values['password'] = password
        values['username'] = username

        p = self._db.add('idp_user', values)

        return self._db.get('idp_user', **values)


    def idp_user(self, id:str) -> dict:
        return self._db.get_by_id('idp_user', id)

    def idp_users(self, **values) -> dict:
        return self._db.get('idp_user', **values)

    def idp_user_update(self, **values) -> dict:
        self._db.update('idp_user', values, {'id': values['id']})

    def idp_user_delete(self, id) -> None:
        self._db.delete('idp_user', id=id)

    def idp_user_purge(self) -> None:
        self._db.purge('idp_user')
##### google_user #####

    def google_user_create(self, email:str, **values) -> dict:

        values['email'] = email

        p = self._db.add('google_user', values)

        return self._db.get('google_user', **values)


    def google_user_create_unique(self, email:str, **values) -> dict:

        values['email'] = email

        return self._db.add_unique('google_user', values, ['email'])


    def google_user(self, id:str) -> dict:
        return self._db.get_by_id('google_user', id)

    def google_users(self, **values) -> dict:
        return self._db.get('google_user', **values)

    def google_user_update(self, **values) -> dict:
        self._db.update('google_user', values, {'id': values['id']})

    def google_user_delete(self, id) -> None:
        self._db.delete('google_user', id=id)

    def google_user_purge(self) -> None:
        self._db.purge('google_user')

