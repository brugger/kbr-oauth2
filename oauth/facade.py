
import oauth.db as db

class DB(db.DB):

    def new_function() -> None:
        print("Add fancy facade stuff here...")
        return

    def idp_user_update_login_date(self, id:str) -> dict:
        q = f"update idp_user set last_login=now() where id = '{id}'"
        self._db.do(q)

