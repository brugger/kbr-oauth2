INSERT INTO acl (endpoint, can_create, can_read, can_update, can_delete) values 
        ('/idp-users/', True, True, True, True);
        

INSERT INTO acl_role (acl_id, role_id) VALUES
    ( (SELECT id from acl WHERE endpoint='/idp-users/' ), (SELECT id from role WHERE name='admin' ));

