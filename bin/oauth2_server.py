#!/usr/bin/env python3

''' REST API for vmail'''

import argparse

import pprint as pp

import kbr.log_utils as logger
import kbr.config_utils as config_utils

import oauth.auth      as oauth
import kbr.tornado       as tornado
import kbr.version_utils as version_utils

version = version_utils.as_string()

#import <PROJECT>.db as <PROJECT>_db

db = None


class RootHandler ( tornado.BaseHandler ):

    def endpoint(self):
        return("/")

    def get(self):

#        self.canRead( self.endpoint() )
        return self.send_response(data={"name":"kbr-oauth2", "version":version})
        self.render('index.html', title='My title', message='Hello world')


def main():
    parser = argparse.ArgumentParser(description='blood_flow_rest: the rest service for blood_flow')


    parser.add_argument('-c', '--config', default="oauth2.json", help="config file, can be overridden by parameters")

    parser.add_argument('-l', '--logfile', default=None, help="Logfile to write to, default is stdout")
    parser.add_argument('-p', '--port', help="Port to bind to")
    parser.add_argument('-v', '--verbose', default=4, action="count",  help="Increase the verbosity of logging output")

    args = parser.parse_args()

    config = config_utils.readin_config_file( args.config )

    if args.port:
        config.server.port = args.port

    if args.logfile:
        config.logfile = args.logfile


    logger.init(name=config.name, log_file=config.logfile )
    logger.set_log_level( args.verbose )

    if 'database' in config:
        global db
#        db = <PROJECT>_db.DB()
#        db.connect( config.database )

    urls = [('/', RootHandler),
            ] + oauth.init( **config.oauth )

    tornado.run_app( urls, **config.server )


if __name__ == "__main__":
    main()
