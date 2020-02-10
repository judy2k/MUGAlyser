#!/usr/bin/env python

'''
mugalyser_main -- Grab MUG Stats and stuff them into a MongoDB Database

29-May-2017 : Changed program to use --collect argument to allow collection of pro, nopro or all
data. Pro and No Pro data are now stored in seperate collections.

@author:     joe@joedrumgoole.com

@license:    AFGPL

'''

import sys
from datetime import datetime
from argparse import ArgumentParser
import logging
import os
import re

import pymongo

from configparser import ConfigParser
from os.path import expanduser

from .meetup_api import MeetupAPI
from .audit import Audit
from .mongodb import MUGAlyserMongoDB
from .meetup_writer import MeetupWriter
from .version import __programName__, __version__
from .logger import Logger
from .auth import ProOAuthProvider

APP_NAME = "mugalyzer"
DEBUG = 1
TESTRUN = 0
PROFILE = 0

class Config:
    config_paths = [
        f"/etc/{APP_NAME}.ini",
        expanduser(f"~/.{APP_NAME}.ini"),
        "config.ini",
    ]

    def __init__(self, path=None):
        self._config = config = ConfigParser()
        if path is not None:
            config_read = config.read([path])
            if config_read == 0:
                raise CLIError(f"Could not load config from: {path}")
        else:
            config.read(self.config_paths)

    @property
    def consumer_id(self):
        return self._config.get("consumer", "id")  # consumer key

    @property
    def consumer_secret(self):
        return self._config.get("consumer", "secret")  # consumer secret

    @property
    def consumer_redirect_uri(self):
        return self._config.get("consumer", "redirecturi")

    @property
    def user_email(self):
        return self._config.get("user", "email")

    @property
    def user_password(self):
        return self._config.get("user", "password")


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''

    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg

    def __str__(self):
        return self.msg

    def __unicode__(self):
        return self.msg


def cleanUp(procs):
    for i in procs:
        i.terminate()
        i.join()


def config_value(namespace, cli_arg_name, flag_name, env_name):
    """
    Provide a value from the CLI or environment.
    
    First attempts to get a value from the provided namespace.
    If the value is None, it falls back to an environment variable.
    If no value can be found, raise an error.
    """


def mugalyser(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    try:
        # Setup argument parser

        parser = ArgumentParser(description='''
Read data from the Meetup API and write it do a MongoDB database. Each run of this program
creates a new batch of data identified by a batchID. The default database is MUGS. You can change
this by using the --host parameter and specifying a different database in the mongodb URI.

If you are and adminstrator on the pro account you should use the --admin flag to give you
access to the admin APIs.
''')
        #
        # MongoDB Args

        parser.add_argument('--host', default="mongodb://localhost:27017/MUGS",
                            help='MongoDB URI to connect to : [default: %(default)s]')
        parser.add_argument("-v", "--version", action='version', version=__programName__ + " " + __version__)
        parser.add_argument('--mugs', nargs="+", default=[],
                            help='Process MUGs list list mugs by name [default: %(default)s]')

        parser.add_argument("--collect", choices=["pro", "nopro", "all"], default="all",
                            help="Use pro API calls, no pro API calls or both")
        parser.add_argument("--admin", default=False, action="store_true",
                            help="Some calls are only available to admin users, use this if you are not an admin")
        parser.add_argument("--database", default="MUGS",
                            help="Default database name to write to [default: %(default)s]")
        parser.add_argument('--phases', nargs="+",
                            choices=["groups", "members", "attendees", "upcomingevents", "pastevents"],
                            default=["all"], help='execution phases')

        parser.add_argument('--loglevel', default="INFO", choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
                            help='Logging level [default: %(default)s]')

        # parser.add_argument('--apikey', default=None, help='Default API key for meetup')

        parser.add_argument("--batchname", default=__programName__, help="Batch name used in creating audit batches")
        parser.add_argument('--urlfile',
                            help="File containing a list of MUG URLs to be used to parse data [ default: %(default)s]")
        parser.add_argument("--drop", default=False, action="store_true",
                            help="drop the database before writing data [default: %(default)s]")
        parser.add_argument(
            "-c", "--config",
            default=None,
            metavar='PATH',
            help="load config from %(metavar)s. [defaults: "+", ".join(Config.config_paths)+"]")

        # parser.add_argument("--organizer_id", type=int, help="Organizer ID is required for non pro groups")
        # OAuth Credentials
        oauth_group = parser.add_argument_group('authentication')
        oauth_group.add_argument("--consumerid", dest='consumer_id', help="Your application's consumer ID.")
        oauth_group.add_argument("--consumersecret", dest='consumer_secret', help="Your application's consumer ID.")
        oauth_group.add_argument("--redirecturi", dest='redirect_uri', help="Your application's redirect URL. (This isn't used, but it is required)")
        oauth_group.add_argument("--useremail", dest='user_email', help="Your Meetup account's email address.")
        oauth_group.add_argument("--userpassword", dest='user_password', help="Your Meetup account's password.")

        # Process arguments
        args = parser.parse_args(argv)
        config = Config()

        consumer_id = args.consumer_id or os.getenv("MEETUP_CONSUMER_ID") or config.consumer_id

        mugalyser_logger = Logger(__programName__, args.loglevel)
        # mugalyser_logger.add_stream_handler( args.loglevel )
        mugalyser_logger.add_file_handler("mugalyser.log", args.loglevel)

        auth_provider = ProOAuthProvider(
            consumer_id=args.consumerid,
            consumer_secret=args.consumersecret,
            consumer_redirect_uri=args.redirecturi,
            user_email=args.useremail,
            user_password=args.userpassword,
        )

        api = MeetupAPI(auth_provider=auth_provider, reshape=True)
        logger = mugalyser_logger.log()

        # Turn off logging for requests
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

        mdb = MUGAlyserMongoDB(uri=args.host, database_name=args.database)

        if args.drop:
            logger.warn(f"Dropping database:'{args.database}'")
            mdb.drop(args.database)

        audit = Audit(mdb)

        batchID = audit.start_batch({"args": vars(args),
                                     "version": __programName__ + " " + __version__,
                                     "name": args.batchname})

        start = datetime.utcnow()
        logger.info("Started MUG processing for batch ID: %i", batchID)
        logger.info("Writing to database : '%s'", mdb.database().name)

        group_dict = {}

        count = 0
        group_list = []
        if args.mugs:
            for url in args.mugs:
                group_list.append(api.get_group(url))
        else:
            group_list = list(api.get_groups())

        for url, group in group_list:

            #print(f"Checking:{group['urlname']}")
            urlname = group['urlname']
            url, full_group = api.get_group(urlname)
            if args.collect in ["pro", "all"]:
                if "pro_network" in full_group and full_group["pro_network"]["name"] == "MongoDB":
                    count = count + 1
                    logger.info(f"{count}. Processing pro group: {group['urlname']}")
                    group_dict[urlname] = full_group

            if args.collect in ["nopro", "all"]:
                if args.organizer_id:
                    if full_group["organizer"]["id"] == args.organizer_id:
                        count = count + 1
                        logger.info(f"{count}. Processing normal group: {group['urlname']}")
                        group_dict[urlname] = full_group
                else:
                    logger.error("You must specify --organizer_id  when collecting nopro groups")
                    sys.exit(1)

        if args.urlfile:
            urlfile = os.path.abspath(args.urlfile)
            logger.info("Reading groups from: '%s'", urlfile)
            with open(urlfile) as f:
                lines = f.read().splitlines()
                # string comments
                regex = "^\s*#.*|^\s*$"  # comments with # or blank lines
                for i in lines:
                    clean_line = i.rstrip()
                    if not re.match(regex, clean_line):
                        group_dict[clean_line] = None

        # scoop up any command line args
        for i in args.mugs:
            group_dict[i] = None

        writer = MeetupWriter(auth_provider, batchID, mdb, reshape=True)

        if "all" in args.phases:
            phases = ["groups", "members", "upcomingevents", "pastevents"]

        else:
            phases = args.phases

        if args.admin:
            logger.info("--admin : we will collect attendee info")
            phases.append("attendees")
        else:
            logger.info("No admin account")
            logger.info("We will not collect attendee info: ignoring attendees")

        logger.info("Processing phases: %s", phases)

        if "groups" in phases:
            logger.info("processing group info for %i groups: collect=%s", len(group_dict), args.collect)
            writer.write_groups(group_dict.keys())
            phases.remove("groups")
        if "members" in phases:
            logger.info("processing members info for %i groups: collect=%s", len(group_dict), args.collect)
            writer.write_members(group_dict.keys())
            phases.remove("members")

        for i in group_dict.keys():
            writer.capture_snapshot(i, args.admin, phases)

        audit.end_batch(batchID)
        end = datetime.utcnow()

        elapsed = end - start

        logger.info("MUG processing took %s for BatchID : %i", elapsed, batchID)

    except KeyboardInterrupt:
        print("Keyboard interrupt : Exiting...")
        sys.exit(2)

    except pymongo.errors.ServerSelectionTimeoutError as e:
        print("Failed to connect to MongoDB Server (server timeout): %s" % e)
        sys.exit(2)


if __name__ == "__main__":
    sys.exit(mugalyser(sys.argv[1:]))
