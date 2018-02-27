"""
SDSKit command line interface.
"""
from __future__ import absolute_import
from __future__ import print_function

import os, importlib, json, yaml, traceback, argparse, logging
from importlib import import_module

import sdscli
from sdscli.log_utils import logger


def get_adapter_module(sds_type, mod_name):
    """Import adapter module."""

    try:
        return import_module('sdscli.adapters.%s.%s' % (sds_type, mod_name))
    except ImportError:
        logger.error('Failed to import adapter module "%s" for SDS type "%s".' % (mod_name, sds_type))
        raise


def get_adapter_func(sds_type, mod_name, func_name):
    """Import adapter function."""

    adapter_mod = get_adapter_module(sds_type, mod_name)
    logger.debug("adapter_mod: %s" % adapter_mod)
    try:
        return getattr(adapter_mod, func_name)
    except AttributeError:
        logger.error('Failed to get function "%s" from adapter module "%s".' % (func_name, adapter_mod))
        raise


def configure(args):
    """Configure SDS config file."""

    logger.debug("got to configure(): %s" % args)
    sds_type = args.type
    logger.debug("sds_type: %s" % sds_type)
    func = get_adapter_func(sds_type, 'configure', 'configure') 
    logger.debug("func: %s" % func)
    func()


def update(args):
    """Update SDS components."""

    logger.debug("got to update(): %s" % args)
    sds_type = args.type
    logger.debug("sds_type: %s" % sds_type)
    func = get_adapter_func(sds_type, 'update', 'update') 
    logger.debug("func: %s" % func)
    func(args.component, args.debug)


def job_list(args):
    """Configure SDS config file."""

    logger.debug("got to job_list(): %s" % args)


def dispatch(args):
    """Dispatch to appropriate function."""

    # turn on debugging
    if args.debug: logger.setLevel(logging.DEBUG)

    logger.debug("args: %s" % args)

    if args.func:
        return args.func(args)
    else:
        logger.error("No func specified for args %s" % args)
        return 1


def main():
    """Process command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debug', '-d', action='store_true', help="turn on debugging")
    subparsers = parser.add_subparsers(help='Functions')

    # parser for configure
    parser_configure = subparsers.add_parser('configure', help="configure SDS config file")
    parser_configure.add_argument('type', default='hysds', const='hysds', nargs='?',
                                  choices=['hysds', 'sdskit'])
    parser_configure.set_defaults(func=configure)

    # parser for update
    parser_update = subparsers.add_parser('update', help="update SDS components")
    parser_update.add_argument('--type', '-t', default='hysds', const='hysds', nargs='?',
                                  choices=['hysds', 'sdskit'])
    parser_update.add_argument('component', choices=['mozart', 'grq', 'metrics', 
                               'factotum', 'ci', 'verdi', 'all'])
    parser_update.set_defaults(func=update)

    # parser for jobs
    parser_job = subparsers.add_parser('job', help="SDS job subcommand")
    job_subparsers = parser_job.add_subparsers(help="Job functions.")

    # parser for jobs listing
    parser_job_list = job_subparsers.add_parser('list', help="list SDS job counts")
    parser_job_list.add_argument("status", help="job status to list counts for")
    parser_job_list.set_defaults(func=job_list)

    # dispatch
    args = parser.parse_args()
    return dispatch(args)


if __name__ == "__main__":
    sys.exit(main())
