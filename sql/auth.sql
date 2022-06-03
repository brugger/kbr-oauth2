create table idp_user (
   id UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   email varchar( 300) UNIQUE NOT NULL,
   password varchar( 200 ) NOT NULL,
   username varchar( 200 ) NOT NULL
);

create table user_profile (
   id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   idp_source integer default 1,
   idp_user_id UUID NOT NULL,
   email varchar(200),
   username varchar( 200 ),
   superuser boolean NOT NULL default False,
   create_date timestamp not null default now(),
   last_login timestamp
);


create table acl (
    id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
    endpoint varchar(50) NOT NULL ,
    can_create boolean default FALSE,
    can_read boolean default False,
    can_update boolean default False,
    can_delete boolean default False
);


create table groups (
    id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
    name varchar( 200 ) UNIQUE NOT NULL
);


create table user_groups (
   id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   user_profile_id UUID NOT NULL references user_profile( id ),
   groups_id UUID NOT NULL references groups( id )
);

create table acl_groups (
    id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
    groups_id UUID NOT NULL references groups( id ),
    acl_id UUID NOT NULL references acl( id )
);
