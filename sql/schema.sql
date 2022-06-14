CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS idp_user (
   id UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   email varchar( 300) UNIQUE NOT NULL,
   password varchar( 200 ) NOT NULL,
   username varchar( 200 ) NOT NULL,
   create_date timestamp default now(),
   last_login timestamp
);

CREATE TABLE IF NOT EXISTS google_user (
   id UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   idp_user_id UUID references idp_user(id),
   gid INT, 
   email varchar(200) NOT NULL,
   username varchar( 200 ),
   create_date timestamp default now(),
   last_login timestamp
);

