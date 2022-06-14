#!/usr/bin/env python3
import argparse
import os
import sys
import csv
import json

sys.path.append(".")

from tabulate import tabulate

from kbr import config_utils
import kbr.crypt_utils as crypt_utils
import kbr.args_utils as args_utils
import kbr.json_utils as json_utils
import kbr.type_utils as type_utils
import kbr.crypt_utils as crypt_utils
import kbr.password_utils as password_utils

import oauth.facade as oauth_db

def config_cmd(args, config_file:str='api.json', force:bool=False) -> None:
    commands = {'c':'create', 'p':'print', 'h':'help'}
    if len(args) == 0:
        args.append('help')

    command = args.pop(0)
    command = args_utils.valid_command(command, commands)

    if command == 'create':
        
        dbname   = args_utils.get_or_fail(args, "database name missing")
        username = args_utils.get_or_default(args, dbname)
        password = args_utils.get_or_default(args, crypt_utils.create_password())
        host     = args_utils.get_or_default(args, "localhost")

        config = {"name": f"{dbname}-api",
                  "database": f"postgresql://{username}:{password}@{host}/{dbname}",
                  "logfile": "api.log",
                  "server": {
                      "port": 8080,
                      "template_path": "templates",
                      "debug": False
                   }
                  }

        if not os.path.isfile(config_file) or force:
           json_utils.write(config_file, config)
        else:
            print(f"Cannot overwrite {config_file}")
            sys.exit(-1)


    elif command == 'print':
        config = dict(config_utils.readin_config_file(config_file))
        print( json.dumps(config, indent=2))
    else:
        print("Help:")
        print("==========================")
        print("config print")
        print("config create  <dbname> [dbuser] [dbpasswd]")
        print("utils help")

        sys.exit(1)



def utils_cmd(args) -> None:
    commands = {'i':'import', 'e':'export', 'h':'help'}

    if len(args.command) == 0:
        args.command.append('help')

    command = args.command.pop(0)
    command = args_utils.valid_command(command, commands)

    if command == 'import':
        print('Not implemented yet...')
    elif command == 'export':
        print('Not implemented yet...')
    else:
        print("utils: {}".format(args_utils.pretty_commands(commands)))
        sys.exit()


def table_cmd(args) -> None:
    commands = { 'i':'idp_user','g':'google_user', 'h':'help'}

    if len(args.command) == 0:
        args.command.append('help')

    command = args.command.pop(0)
    command = args_utils.valid_command(command, commands)
    
    
    if command == 'idp_user':
        idp_user_cmd(args.command)
        
    elif command == 'google_user':
        google_user_cmd(args.command)
        
    else:
        print("table: {}".format(args_utils.pretty_commands(commands)))
        sys.exit()



def idp_user_cmd(args) -> None:

    commands = {'c':'create', 's':'show', 'l':'list', 'u':'update', 'd': 'delete', 'p':'purge', 'h':'help'}

    if len(args) == 0:
        args.append('help')

    command = args.pop(0)
    command = args_utils.valid_command(command, commands)

    if command == 'create':
        data = {}

        data['email'] = args_utils.get_or_fail(args, "Missing email")
        data['password'] = password_utils.hash_password(args_utils.get_or_fail(args, "Missing password"))
        data['username'] = args_utils.get_or_fail(args, "Missing username")


        db.idp_user_create(**data)
#        db.idp_user_create(email=email, password=password, username=username, create_date=create_date, last_login=last_login)

    elif command == 'show':
        id = args_utils.get_or_fail(args, "Missing idp_user id")
        entry = db.idp_user(id)
        print( tabulate(entry, headers={}, tablefmt='psql'))

    elif command == 'list':
        idp_users = db.idp_users()
        print( tabulate(idp_users, headers={}, tablefmt='psql'))

    elif command == 'update':
        id = args_utils.get_or_fail(args, "Missing idp_user id")
        data = args_utils.group_args( args )
        data['id'] = id
        del data['rest']

        db.idp_user_update(**data)

    elif command == 'delete':
        id = args_utils.get_or_fail(args, "Missing idp_user id")
        db.idp_user_delete(id)
    elif command == 'purge':
        db.idp_user_purge()

    else:
        print("Help:")
        print("-----------------")
        print("idp_user list")
        print("idp_user create [email] [password] [username] <create_date> <last_login> ")
        print("idp_user show [id]")
        print("idp_user update [id] email:email password:password username:username create_date:create_date last_login:last_login  ")
        print("idp_user delete [id]")
        print("idp_user purge")
        sys.exit()


def google_user_cmd(args) -> None:

    commands = {'c':'create', 's':'show', 'l':'list', 'u':'update', 'd': 'delete', 'p':'purge', 'h':'help'}

    if len(args) == 0:
        args.append('help')

    command = args.pop(0)
    command = args_utils.valid_command(command, commands)

    if command == 'create':
        data = {}

        data['email'] = args_utils.get_or_fail(args, "Missing email")

        data['idp_user_id'] = args_utils.get_or_default(args, None)
        data['gid'] = args_utils.get_or_default(args, None)
        data['username'] = args_utils.get_or_default(args, None)

        if data['gid'] is None:
            del data['gid']

        if data['username'] is None:
            del data['username']

        db.google_user_create(**data)
#        db.google_user_create(idp_user_id=idp_user_id, gid=gid, email=email, username=username, create_date=create_date, last_login=last_login)

    elif command == 'show':
        id = args_utils.get_or_fail(args, "Missing google_user id")
        entry = db.google_user(id)
        print( tabulate(entry, headers={}, tablefmt='psql'))

    elif command == 'list':
        google_users = db.google_users()
        print( tabulate(google_users, headers={}, tablefmt='psql'))

    elif command == 'update':
        id = args_utils.get_or_fail(args, "Missing google_user id")
        data = args_utils.group_args( args )
        data['id'] = id
        del data['rest']

        db.google_user_update(**data)

    elif command == 'delete':
        id = args_utils.get_or_fail(args, "Missing google_user id")
        db.google_user_delete(id)
    elif command == 'purge':
        db.google_user_purge()

    else:
        print("Help:")
        print("-----------------")
        print("google_user list")
        print("google_user create [email] <idp_user_id> <gid> <username> <create_date> <last_login> ")
        print("google_user show [id]")
        print("google_user update [id] email:email idp_user_id:idp_user_id gid:gid username:username create_date:create_date last_login:last_login  ")
        print("google_user delete [id]")
        print("google_user purge")
        sys.exit()





def main():

    commands = {'u':'utils', 't':'table', 'c':'config', 'h':'help'}

    parser = argparse.ArgumentParser(description='{project}-cli tool')
    parser.add_argument('-c', '--config', default="oauth2.json", help="config file, can be overridden by parameters")
    parser.add_argument('-f', '--force', default=False, action="store_true", help="overwrite files if exists")
    parser.add_argument('-i', '--ids', default=False, action="store_true", help="Only output IDs on lists")
    parser.add_argument('command', nargs='*', help="{}".format(",".join(commands.values())))

    args = parser.parse_args()

    args_utils.min_count(1, len(args.command),
                         msg="oauth-cli takes one of the following commands: {}".format(args_utils.pretty_commands(commands)))


    if len(args.command) == 0:
        args.command.append('help')

    command = args.command.pop(0)
    command = args_utils.valid_command(command, commands)

    if command == 'config':
        config_cmd(args.command, args.config, args.force)
        sys.exit()

    args.config = config_utils.readin_config_file( args.config )

    global db
    db = oauth_db.DB()
    db.connect( args.config.database )

    if command == 'utils':
        utils_cmd(args)
    elif command == 'table':
        table_cmd(args)
    elif command == 'help':
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()


