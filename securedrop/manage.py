#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import fnmatch
from getpass import getpass
import os
import shutil
import signal
import subprocess
import sys
import traceback

import psutil
import qrcode
from sqlalchemy.orm.exc import NoResultFound

from db import db_session, Journalist
from management import run

ABS_MODULE_PATH = os.path.dirname(os.path.abspath(__file__))
# We need to import config in each function because we're running the tests
# directly, so it's important to set the environment correctly, depending on
# development or testing, before importing config.
os.environ['SECUREDROP_ENV'] = 'dev'

# TODO: the PID file for the redis worker is hard-coded below.
# Ideally this constant would be provided by a test harness.
# It has been intentionally omitted from `config.py.example`
# in order to isolate the test vars from prod vars.
# When refactoring the test suite, the TEST_WORKER_PIDFILE
# TEST_WORKER_PIDFILE is also hard-coded in `tests/common.py`.
TEST_WORKER_PIDFILE = "/tmp/securedrop_test_worker.pid"


def _get_pid_from_file(pid_file_name): # pragma: no cover
    try:
        return int(open(pid_file_name).read())
    except IOError:
        return None


def _start_test_rqworker(config): # pragma: no cover
    if not psutil.pid_exists(_get_pid_from_file(TEST_WORKER_PIDFILE)):
        tmp_logfile = open("/tmp/test_rqworker.log", "w")
        subprocess.Popen(["rqworker", "test",
                          "-P", config.SECUREDROP_ROOT,
                          "--pid", TEST_WORKER_PIDFILE],
                         stdout=tmp_logfile,
                         stderr=subprocess.STDOUT)


def _stop_test_rqworker(): # pragma: no cover
    rqworker_pid = _get_pid_from_file(TEST_WORKER_PIDFILE)
    if rqworker_pid:
        os.kill(rqworker_pid, signal.SIGTERM)
        try:
            os.remove(TEST_WORKER_PIDFILE)
        except OSError:
            pass


def _cleanup_test_securedrop_dataroot(config): # pragma: no cover
    # Keyboard interrupts or dropping to pdb after a test failure sometimes
    # result in the temporary test SecureDrop data root not being deleted.
    if os.environ['SECUREDROP_ENV'] == 'test':
        try:
            shutil.rmtree(config.SECUREDROP_DATA_ROOT)
        except OSError:
            pass


def _cleanup_test_environment(config): # pragma: no cover
    _stop_test_rqworker()
    _cleanup_test_securedrop_dataroot(config)


def _run_in_test_environment(cmd): # pragma: no cover
    """Handles setting up and tearing down the necessary environment to run
    tests."""
    os.environ['SECUREDROP_ENV'] = 'test'
    import config
    _start_test_rqworker(config)
    try:
        test_rc = int(subprocess.call(cmd, shell=True))
        return test_rc
    finally:
        _cleanup_test_environment(config)


def _get_test_module_dict(type):
    """A convenience function that allows a user to pass, e.g.,
    "journalist" instead of "tests/test_unit_journalist.py". Returns a
    :obj:`dict` mapping of module keywords to absolute module paths.
    
    :param str type: The type, either 'functional' or 'unit' of tests to
                     gather.
    """
    tests, test_paths = [], []

    if type == 'functional':
        test_dir = os.path.join(ABS_MODULE_PATH, 'tests', 'functional')
        prefix = 'test_'
    elif type == 'unit':
        test_dir = os.path.join(ABS_MODULE_PATH, 'tests')
        prefix = 'test_unit_'
        # Add irregularly named unit tests. TODO: consider combining journalist
        # unit tests and dropping 'unit' from all unit tests.
        tests += ['test_journalist', 'test_single_star']
        test_paths += [os.path.join(test_dir, test + '.py')
                       for test in tests]
        
    for file in os.listdir(test_dir):
        if fnmatch.fnmatch(file, prefix + '*'):
            tests.append(file[len(prefix):-len('.py')])
            test_paths.append(os.path.join(test_dir, file))

    return dict(zip(tests, test_paths))


def test(): # pragma: no cover
    """Runs both functional and unit tests."""
    return _run_in_test_environment("pytest --cov")


def functional_test(args):
    """Runs the functional tests."""
    # -l/--list
    if getattr(args, "list", False):
        print(list(_get_test_module_dict("functional")))
        return 0

    cmd = 'pytest '
    # -a/--all
    if getattr(args, "all", False): # pragma: no cover
        cmd += '--cov '
        cmd += ' '.join(_get_test_module_dict('functional').values())
    # Run unit tests related to a single module
    elif getattr(args, "functional", False): # pragma: no cover
        unit_path = _get_test_module_dict('functional')[args.unit]
        cmd += unit_path
    # Any additional arguments to be passed through to pytest
    if getattr(args, "pytest_args", False):
        cmd += ' '.join(args.pytest_args)
    # Run unit tests related to a single module
    elif getattr(args, "unit", False): # pragma: no cover
        try:
            unit_path = _get_test_module_dict('functional')[args.unit]
        except KeyError:
            print('No functional test "{}" found. To list all unit tests run '
                  '`./manage.py unit -l`.'.format(args.unit))
            return 1
        else:
            cmd += module_path
    # Any additional arguments to be passed through to pytest
    if getattr(args, "pytest_args", False): # pragma: no cover
        cmd += ' '.join(args.pytest_args)

    return _run_in_test_environment(cmd)


def unit_test(args):
    """Runs the unit tests."""
    # -l/--list
    if getattr(args, 'list', False):
        print(list(_get_test_module_dict('unit')))
        return 0
 
    cmd = 'pytest '
    # -a/--all
    if getattr(args, "-a", False): # pragma: no cover
        cmd += '--cov --ignore={}'.format(
            os.path.join(ABS_MODULE_PATH, 'tests', 'functional'))
    # Run unit tests related to a single module
    elif getattr(args, "unit", False): # pragma: no cover
        try:
            module_path = _get_test_module_dict('unit')[args.unit]
        except KeyError:
            print('No unit test "{}" found. To list all unit tests run '
                  '`./manage.py unit -l`.'.format(args.unit))
            return 1
        else:
            cmd += module_path
    # Any additional arguments to be passed through to pytest
    if getattr(args, 'pytest_args', False): # pragma: no cover
        cmd += ' '.join(args.pytest_args)

    return _run_in_test_environment(cmd)


def reset(): # pragma: no cover
    """Clears the SecureDrop development applications' state, restoring them to
    the way they were immediately after running `setup_dev.sh`. This command:
    1. Erases the development sqlite database file.
    2. Regenerates the database.
    3. Erases stored submissions and replies from the store dir.
    """
    import config
    import db

    # Erase the development db file
    assert hasattr(config, 'DATABASE_FILE'), ("TODO: ./manage.py doesn't know "
                                              "how to clear the db if the "
                                              "backend is not sqlite")
    os.remove(config.DATABASE_FILE)

    # Regenerate the database
    db.init_db()

    # Clear submission/reply storage
    for source_dir in os.listdir(config.STORE_DIR):
        # Each entry in STORE_DIR is a directory corresponding to a source
        shutil.rmtree(os.path.join(config.STORE_DIR, source_dir))
    return 0


def add_admin():
    return _add_user(is_admin=True)


def add_journalist():
    return _add_user()


def _add_user(is_admin=False):
    while True:
        username = raw_input("Username: ")
        if Journalist.query.filter_by(username=username).first():
            print "Sorry, that username is already in use."
        else:
            break

    while True:
        password = getpass("Password: ")
        password_again = getpass("Confirm Password: ")

        if len(password) > Journalist.MAX_PASSWORD_LEN:
            print ("Your password is too long (maximum length {} characters). "
                   "Please pick a shorter password.".format(
                   Journalist.MAX_PASSWORD_LEN))
            continue

        if password == password_again:
            break
        print "Passwords didn't match!"

    hotp_input = raw_input("Will this user be using a YubiKey [HOTP]? (y/N): ")
    otp_secret = None
    if hotp_input.lower() in ('y', 'yes'):
        while True:
            otp_secret = raw_input(
                "Please configure your YubiKey and enter the secret: ")
            if otp_secret:
                break

    try:
        user = Journalist(username=username,
                          password=password,
                          is_admin=is_admin,
                          otp_secret=otp_secret)
        db_session.add(user)
        db_session.commit()
    except Exception as exc:
        if "username is not unique" in str(exc):
            print "ERROR: That username is already taken!"
        else:
            print('ERROR: An unexpected error occurred, traceback:')
            traceback.print_exc()
        return 1
    else:
        print 'User "{}" successfully added'.format(username)
        if not otp_secret:
            # Print the QR code for Google Authenticator
            print("\nScan the QR code below with Google Authenticator:\n")
            uri = admin.totp.provisioning_uri(username, issuer_name="SecureDrop")
            qr = qrcode.QRCode()
            qr.add_data(uri)
            qr.print_ascii(tty=sys.stdout.isatty())
            print('\nIf the barcode does not render correctly, try changing '
                  "your terminal's font (Monospace for Linux, Menlo for OS X)."
                  'If you are using iTerm on Mac OS X, you will need to '
                  'change the "Non-ASCII Font", which is your profile\'s Text'
                  'settings.')
            print("\nCan't scan the barcode? Enter following shared secret "
                  'manually:\n{admin.formatted_otp_secret}\n')
        return 0


def delete_user():
    """Deletes a journalist or administrator from the application."""
    while True:
        username = raw_input("Username to delete: ")
        try:
            selected_user = Journalist.query.filter_by(username=username).one()
            break
        except NoResultFound:
            print "ERROR: That user was not found!"

    db_session.delete(selected_user)
    db_session.commit()
    print "User '{}' successfully deleted".format(username)
    return 0


def clean_tmp(): # pragma: no cover
    """Cleanup the SecureDrop temp directory. This is intended to be run
    as an automated cron job. We skip files that are currently in use to
    avoid deleting files that are currently being downloaded."""
    # Inspired by http://stackoverflow.com/a/11115521/1093000
    import config

    def file_in_use(fname):
        in_use = False

        for proc in psutil.process_iter():
            try:
                open_files = proc.open_files()
                in_use = in_use or any([open_file.path == fname
                                        for open_file in open_files])
                # Early return for perf
                if in_use:
                    break
            except psutil.NoSuchProcess:
                # This catches a race condition where a process ends before we
                # can examine its files. Ignore this - if the process ended, it
                # can't be using fname, so this won't cause an error.
                pass

        return in_use


    def listdir_fullpath(d):
        # Thanks to http://stackoverflow.com/a/120948/1093000
        return [os.path.join(d, f) for f in os.listdir(d)]

    for path in listdir_fullpath(config.TEMP_DIR):
        if not file_in_use(path):
            os.remove(path)

    return 0


def get_args():
    parser = argparse.ArgumentParser(prog=__file__, description='Management '
                                     'and testing for SecureDrop.')
    subps = parser.add_subparsers()
    # Run 1+ unit tests with pytest--pass options
    unit_subp = subps.add_parser('unit', help='Run 1+ unit tests with '
                                 'options (see subcommand help).')
    unit_subp.set_defaults(func=unit_test)
    unit_excl = unit_subp.add_mutually_exclusive_group(required=True)
    unit_excl.add_argument('-a', '--all', action='store_true',
                           help='Run all unit tests with coverage report.')
    unit_excl.add_argument('-l', '--list', action='store_true',
                           help='List all unit tests.')
    unit_excl.add_argument('unit', nargs='?', help='Run a unit test. See -l to'
                           'list unit tests.')
    unit_subp.add_argument('pytest_args', nargs=argparse.REMAINDER,
                           help='Any trailing args are passed to pytest '
                           '(--pdb, -x, --ff, etc.).')
    # Run 1+ functional tests with pytest--pass options
    functional_subp = subps.add_parser('functional', help='Run 1+ functional '
                                       'tests (see subcommand help).')
    functional_subp.set_defaults(func=functional_test)
    functional_excl = functional_subp.add_mutually_exclusive_group(
        required=True)
    functional_excl.add_argument('-a', '--all', action='store_true',
                           help='Run all functional tests with coverage report.')
    functional_excl.add_argument('-l', '--list', action='store_true',
                           help='List all functional tests.')
    functional_excl.add_argument('functional', nargs='?', help='Run a functional test. See -l to'
                           'list functional tests.')
    functional_subp.add_argument('pytest_args', nargs=argparse.REMAINDER,
                           help='Any trailing args are passed to pytest '
                           '(--pdb, -x, --ff, etc.).')
    # Run the full test suite
    test_subp = subps.add_parser('test', help='Run the full test suite.')
    test_subp.set_defaults(func=test)
    # Run WSGI app
    run_subp = subps.add_parser('run', help='Run the werkzeug source & '
                                'journalist WSGI apps.')
    run_subp.set_defaults(func=run)
    # Add/remove journalists + admins
    admin_subp = subps.add_parser('add-admin', help='Add an admin to the '
                                  'application.')
    admin_subp.set_defaults(func=add_admin)
    journalist_subp = subps.add_parser('add-journalist', help='Add a '
                                       'journalist to the application.')
    journalist_subp.set_defaults(func=add_admin)
    delete_user_subp = subps.add_parser('delete-user', help='Delete a user '
                                        'from the application')
    delete_user_subp.set_defaults(func=delete_user)

    # Reset application state
    reset_subp = subps.add_parser('reset', help='DANGER!!! Clears the '
                                  "SecureDrop application's state.")
    reset_subp.set_defaults(func=reset)
    # Cleanup the SD temp dir
    clean_tmp_subp = subps.add_parser('clean-tmp', help='Cleanup the '
                                      'SecureDrop temp directory.')
    clean_tmp_subp.set_defaults(func=clean_tmp)

    return parser


def _run_from_commandline(): # pragma: no cover
    try:
        args = get_args().parse_args()
        if len(args._get_kwargs()) > 1:
            rc = args.func(args)
        else:
            rc = args.func()
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(signal.SIGINT)
    finally: 
        _stop_test_rqworker()


if __name__ == "__main__": # pragma: no cover
    _run_from_commandline()
