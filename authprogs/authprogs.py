# vim: ts=4 et
"""authprogs: SSH command authenticator module.
# vim: set ts=4 et

Used to restrict which commands can be run via trusted SSH keys."""

#    Copyright (C) 2013 Bri Hatch (daethnir) <bri@ifokr.org>
#
#    This file is part of authprogs.
#
#    Authprogs is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License v2 as published by
#    the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


from . import rsync as rsync_checker
from . import scp as scp_checker

import argparse
import glob
import io
import ipaddress
import os
import pprint
import re
import shutil
import subprocess
import sys
import textwrap
import time
import traceback
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

if sys.version_info.major >= 3:
    unicode = lambda x: x


def pretty(thing):
    """Return pretty-printable version."""
    ppthing = pprint.PrettyPrinter(indent=4)
    return ppthing.pformat(thing)


class Error(Exception):
    """authprogs error class."""

    pass


class SSHEnvironmentError(Error):
    """Problem with the SSH server-side environment.

    These error messages are show directly to users, so be
    cautious in what you say.
    """

    pass


class ConfigError(Error):
    """Problem with the authprogs configuration."""

    pass


class CommandRejected(Error):
    """Client command rejected.

    These error messages are show directly to users, so be
    cautious in what you say.
    """

    pass


class InstallError(Error):
    """Problem with the installing an authorized_keys entry."""

    pass


class AuthProgs(object):  # pylint: disable-msg=R0902
    """AuthProgs class"""

    def __init__(
        self,
        logfile=None,
        configfile=None,
        configdir=None,
        debug=False,
        **kwargs
    ):
        """AuthProgs constructor.

        kwargs include:
            authprogs_binary: path to this binary, when creating
                              authorized_keys entries.
                              If not specified, determines from sys.argv[0]
            name: the name of this key, for matching in rules.
        """

        self.debug = debug
        self.logfile = logfile
        self.client_ip = None
        self.silent = kwargs.get('silent')
        if logfile:
            self.logfh = open(logfile, 'a')
        else:
            self.logfh = False

        # Stores result of shutils.which
        # key is program name, val is realpath.
        self.which_cache = {}

        if kwargs.get('authprogs_binary'):
            self.authprogs_binary = kwargs['authprogs_binary']
        else:
            self.authprogs_binary = os.path.abspath(
                os.path.abspath(sys.argv[0])
            )

        self.original_command_string = os.environ.get(
            'SSH_ORIGINAL_COMMAND', ''
        )

        self.original_command_list = self.original_command_string.split()

        self.keyname = kwargs.get('keyname')
        if not self.keyname:
            self.keyname = ''
        if ' ' in self.keyname or '\t' in self.keyname:
            self.log('FATAL: keyname contains space/tabs\n')
            raise Error('--keyname may contain neither spaces nor tabs.')

        self.yamldocs = None
        self.configfile = configfile
        self.configdir = configdir

        self.subvalidators = {}
        self.subvalidators['rsync'] = rsync_checker.RsyncValidator(self)
        self.subvalidators['scp'] = scp_checker.ScpValidator(self)

    def __del__(self):
        if self.logfh:
            self.logfh.close()

    def raise_and_log_error(self, error, message):
        """Raise error, including message and original traceback.

        error: the error to raise
        message: the user-facing error message
        """
        self.log(
            'raising {}, traceback {}\n'.format(error, traceback.format_exc())
        )
        raise error(message)

    def get_client_ip(self):
        """Return the client IP from the environment."""

        if self.client_ip:
            return self.client_ip

        try:
            client = os.environ.get(
                'SSH_CONNECTION', os.environ.get('SSH_CLIENT')
            )
            self.client_ip = client.split()[0]
            self.logdebug('client_ip: {}\n'.format(self.client_ip))
            return self.client_ip
        except:
            raise SSHEnvironmentError(
                'cannot identify the ssh client IP address'
            )

    def logdebug(self, message):
        """Log debugging information."""
        if self.debug:
            self.log(message)

    def log(self, message):
        """Log information."""
        if self.logfh:
            self.logfh.write(message)  # pylint: disable-msg=E1103

    def _glob(self, path):
        """Return glob results of path, or original if no match

        glob.glob returns a list only if there are actual matching files.
        So we always return the original if glob doesn't succeed
        so we can create files that don't yet exist, etc.

        Mocked out in unit tests, silly otherwise.
        """
        results = glob.glob(path)
        return glob.glob(path) or path

    def _os_path_abspath(self, path):
        """Return abspath of path

        Mocked out in unit tests, silly otherwise.
        """
        return os.path.abspath(path)

    def _os_path_expanduser(self, path):
        """Return pathname with ~ expansions.

        Mocked out in unit tests, silly otherwise.
        """
        return os.path.expanduser(path)

    def _os_path_realpath(self, path):
        """Return canonical pathname.

        Mocked out in unit tests, silly otherwise.
        """
        return os.path.realpath(path)

    def globpaths(self, path, expanduser=False, realpath=False):
        """Return paths for given file name after glob expansion.

        If expanduser is set then expand ~ to current user's home dir
        If realpath is set then convert to real path after resolving symlinks
        Always calls abspath to create a path that starts at / and resolve ..

        Perform glob expansion of name and returns list of canonicalised
        file names
        """
        path = self._os_path_abspath(path)

        if expanduser:
            path = self._os_path_expanduser(path)

        if realpath:
            path = self.realpath(path)

        paths = self._glob(path)

        return paths

    def realpath(self, path):
        """Return the real path for the given file path.

        Returns canonicalised file name (eliminate symlinks, handle '..')
        """
        return self._os_path_realpath(path)

    def check_keyname(self, rule):
        """If a key name is specified, verify it is permitted."""

        keynames = rule.get('keynames')
        if not keynames:
            self.logdebug('no keynames requirement.\n')
            return True
        if not isinstance(keynames, list):
            keynames = [keynames]

        if self.keyname in keynames:
            self.logdebug('keyname "{}" matches rule.\n'.format(self.keyname))
            return True
        else:
            self.logdebug(
                'keyname "{}" does not match rule.\n'.format(self.keyname)
            )
            return False

    def check_client_ip(self, rule):
        """If a client IP is specified, verify it is permitted."""

        if not rule.get('from'):
            self.logdebug('no "from" requirement.\n')
            return True

        allow_from = rule.get('from')
        if not isinstance(allow_from, list):
            allow_from = [allow_from]

        def ipnet(addr):
            addr = unicode(addr)
            if addr.lower() in ('*', 'any'):
                addr = '0.0.0.0/0'
            try:
                return ipaddress.ip_network(addr, strict=False)
            except ValueError:
                return None

        allow_from = [ipnet(x) for x in allow_from]
        allow_from = filter(lambda x: x, allow_from)
        client_ip = ipaddress.ip_address(unicode(self.get_client_ip()))

        for allow in allow_from:
            if client_ip in allow:
                self.logdebug('client_ip {} in {}\n'.format(client_ip, allow))
                return True
        self.logdebug('client_ip {} not in {}'.format(client_ip, allow_from))
        return False

    def get_merged_config(self):
        """Get merged config file.

        Returns an open StringIO containing the
        merged config file.
        """
        if self.yamldocs:
            return

        loadfiles = []
        if self.configfile:
            loadfiles.append(self.configfile)

        if self.configdir:
            # Gets list of all non-dotfile files from configdir.
            loadfiles.extend(
                [
                    f
                    for f in [
                        os.path.join(self.configdir, x)
                        for x in os.listdir(self.configdir)
                    ]
                    if os.path.isfile(f)
                    and not os.path.basename(f).startswith('.')
                ]
            )

        merged_configfile = io.StringIO()
        merged_configfile.write('-\n')
        for thefile in loadfiles:
            self.logdebug('reading in config file {}\n'.format(thefile))
            with open(thefile, 'r') as merge:
                merged_configfile.write(merge.read())
            merged_configfile.write('\n-\n')
        merged_configfile.seek(0)
        self.logdebug(
            'merged log file: """\n{}\n"""\n'.format(merged_configfile.read())
        )
        merged_configfile.seek(0)
        return merged_configfile

    def load(self):
        """Load our config, log and raise on error."""
        try:
            merged_configfile = self.get_merged_config()
            self.yamldocs = yaml.load(merged_configfile, Loader=Loader)
            merged_configfile.close()

            # Strip out the top level 'None's we get from concatenation.
            # Functionally not required, but makes dumps cleaner.
            self.yamldocs = [x for x in self.yamldocs if x]
            self.logdebug('parsed_rules:\n{}\n'.format(pretty(self.yamldocs)))

        except (yaml.scanner.ScannerError, yaml.parser.ParserError):
            self.raise_and_log_error(ConfigError, 'error parsing config.')

    def dump_config(self):
        """Pretty print the configuration dict to stdout."""
        yaml_content = self.get_merged_config()
        print(
            'Configuration Source:\n\t{}\n'.format(
                yaml_content.read().replace('\n', '\n\t')
            )
        )
        yaml_content.close()

        try:
            self.load()
            print(
                'Effective Configuration\n\t{}\n'.format(
                    pretty(self.yamldocs).replace('\n', '\n\t')
                )
            )
        except ConfigError:
            sys.stderr.write(
                'config parse error. try running with --logfile=/dev/tty\n'
            )
            raise

    def install_key_data(self, keydata, target):
        """Install the key data into the open file."""

        target.seek(0)
        contents = target.read()
        ssh_opts = 'no-port-forwarding'
        keydata = keydata.strip()
        if keydata in contents:
            raise InstallError(
                'key data already in file - refusing to double-install.\n'
            )
        if '\n' in keydata:
            raise InstallError(
                'install file does not appear to be an ssh pubkey\n'
            )
        command = '{} --run'.format(self.authprogs_binary)
        if self.logfile:
            command += ' --logfile={}'.format(self.logfile)
        if self.keyname:
            command += ' --keyname={}'.format(self.keyname)

        target.write(
            'command="{command}",{ssh_opts} {keydata}\n'.format(
                command=command, keydata=keydata, ssh_opts=ssh_opts
            )
        )

    def install_key(self, keyfile, authorized_keys):
        """Install a key into the authorized_keys file."""

        # Make the directory containing the authorized_keys
        # file, if it doesn't exist. (Typically ~/.ssh).
        # Ignore errors; we'll fail shortly if we can't
        # create the authkeys file.
        try:
            os.makedirs(os.path.dirname(authorized_keys), 0o700)
        except OSError:
            pass

        keydata = open(keyfile).read()
        target_fd = os.open(authorized_keys, os.O_RDWR | os.O_CREAT, 0o600)
        self.install_key_data(keydata, os.fdopen(target_fd, 'w+'))

    def find_match_rsync(self, rule):  # pylint: disable-msg=R0911,R0912
        """Handle rsync commands."""
        return self.subvalidators['rsync'].validate_command(
            self.original_command_list[:], rule
        )

    def _whichbin(self, name):
        """shutil.which wrapper for unit test mocking."""
        return shutil.which(name)

    def valid_binary(self, name, allowed):
        """Determine if name is a valid binary in allowed.

        Does realpath expansion and returns actual pathname.
        """
        # Return from cache if set and allowed
        if name in self.which_cache:
            if self.which_cache[name] in allowed:
                return self.which_cache[name]
            else:
                return
        else:
            self.which_cache[name] = None

        # Find it in our path
        foundbin = self._whichbin(name)

        if not foundbin:
            return

        # Convert to realpath, store, and return
        foundbin = os.path.realpath(foundbin)
        if foundbin not in allowed:
            return

        # Store this successful name in cache
        self.which_cache[name] = foundbin
        return foundbin

    def find_match_scp(self, rule):  # pylint: disable-msg=R0911,R0912
        """Handle scp commands."""
        return self.subvalidators['scp'].validate_command(
            self.original_command_list[:], rule
        )

    def find_match_command(self, rule):
        """Return a matching (possibly munged) command, if found in rule."""

        command_string = rule['command']
        command_list = command_string.split()

        self.logdebug(
            'comparing "{}" to "{}"\n'.format(
                command_list, self.original_command_list
            )
        )
        if rule.get('allow_trailing_args'):
            self.logdebug(
                'allow_trailing_args is true - comparing initial list.\n'
            )
            # Verify the initial arguments are all the same
            if self.original_command_list[: len(command_list)] == command_list:
                self.logdebug('initial list is same\n')
                return {'command': self.original_command_list}
            else:
                self.logdebug('initial list is not same\n')

        elif rule.get('pcre_match'):
            if re.search(command_string, self.original_command_string):
                return {'command': self.original_command_list}

        elif command_list == self.original_command_list:
            return {'command': command_list}

    def find_match(self):
        """Load the config and find a matching rule.

        returns the results of find_match_command, a dict of
        the command and (in the future) other metadata.
        """

        self.load()
        for yamldoc in self.yamldocs:
            self.logdebug('\nchecking rule """{}"""\n'.format(yamldoc))

            if not yamldoc:
                continue

            if not self.check_client_ip(yamldoc):
                # Rejected - Client IP does not match
                continue

            if not self.check_keyname(yamldoc):
                # Rejected - keyname does not match
                continue

            rules = yamldoc.get('allow')
            if not isinstance(rules, list):
                rules = [rules]

            for rule in rules:
                rule_type = rule.get('rule_type', 'command')
                if rule_type == 'command':
                    sub = self.find_match_command
                elif rule_type == 'scp':
                    sub = self.find_match_scp
                elif rule_type == 'rsync':
                    sub = self.find_match_rsync
                else:
                    self.log(
                        'fatal: no such rule_type "{}"\n'.format(rule_type)
                    )
                    self.raise_and_log_error(
                        ConfigError, 'error parsing config.'
                    )

                match = sub(rule)
                if match:
                    return match

        # No matches, time to give up.
        if not self.silent:
            sys.stderr.write(
                'command "{}" rejected.\n'.format(self.original_command_string)
            )
        raise CommandRejected(
            'command "{}" denied.'.format(self.original_command_string)
        )

    def exec_command(self):
        """Glean the command to run and exec.

        On problems, sys.exit.
        This method should *never* return.
        """
        if not self.original_command_string:
            raise SSHEnvironmentError(
                'no SSH command found; interactive shell disallowed.'
            )

        command_info = {
            'from': self.get_client_ip(),
            'keyname': self.keyname,
            'ssh_original_command': self.original_command_string,
            'time': time.time(),
        }

        os.environ['AUTHPROGS_KEYNAME'] = self.keyname

        retcode = 126
        try:
            match = self.find_match()
            command_info['command'] = match.get('command')
            self.logdebug('find_match returned "{}"\n'.format(match))

            command = match['command']
            retcode = subprocess.call(command)
            command_info['code'] = retcode
            self.log('result: {}\n'.format(command_info))
            sys.exit(retcode)
        except (CommandRejected, OSError) as err:
            command_info['exception'] = '{}'.format(err)
            self.log('result: {}\n'.format(command_info))
            sys.exit(retcode)


def main():  # pylint: disable-msg=R0912,R0915
    """Main."""
    parser = argparse.ArgumentParser()
    parser.usage = textwrap.dedent(
        """\
    %(prog)s {--run|--install_key|--dump_config} [options]

    SSH command authenticator.

    Used to restrict which commands can be run via trusted SSH keys.
    """
    )

    group = parser.add_argument_group(
        'Run Mode Options',
        'These options determine in which mode the authprogs program runs.',
    )
    group.add_argument(
        '-r',
        '--run',
        dest='run',
        action='store_true',
        help='Act as ssh command authenticator. Use this '
        'when calling from authorized_keys.',
    )
    group.add_argument(
        '--dump_config',
        dest='dump_config',
        action='store_true',
        help='Dump configuration (python format) to standard out and exit.',
    )
    group.add_argument(
        '--install_key',
        dest='install_key',
        help='Install the named ssh public key file to authorized_keys.',
        metavar='FILE',
    )

    group = parser.add_argument_group('Other Options')
    group.add_argument(
        '--keyname',
        dest='keyname',
        help='Name for this key, used when matching config blocks.',
    )
    group.add_argument(
        '--configfile',
        dest='configfile',
        help='Path to authprogs configuration file. '
        'Defaults to ~/.ssh/authprogs.yaml',
        metavar='FILE',
    )
    group.add_argument(
        '--configdir',
        dest='configdir',
        help='Path to authprogs configuration directory. '
        'Defaults to ~/.ssh/authprogs.d',
        metavar='DIR',
    )
    group.add_argument(
        '--logfile',
        dest='logfile',
        help='Write logging info to this file. Defaults to no logging.',
        metavar='FILE',
    )
    group.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='Write additional debugging information to --logfile',
    )
    group.add_argument(
        '--silent',
        dest='silent',
        action='store_true',
        help='Do not tell user their command was rejected on failure.',
    )
    group.add_argument(
        '--authorized_keys',
        dest='authorized_keys',
        default=os.path.expanduser('~/.ssh/authorized_keys'),
        help='Location of authorized_keys file for '
        '--install_key. Defaults to ~/.ssh/authorized_keys',
        metavar='FILE',
    )
    group.add_argument(
        '--version', action='store_true', help='Show version and exit.'
    )

    args = parser.parse_args()

    if args.version:
        from . import __version__

        print(__version__)
        sys.exit()

    if not args.configfile:
        cfg = os.path.expanduser('~/.ssh/authprogs.yaml')
        if os.path.isfile(cfg):
            args.configfile = cfg
    if not args.configdir:
        cfg = os.path.expanduser('~/.ssh/authprogs.d')
        if os.path.isdir(cfg):
            args.configdir = cfg

    if args.debug and not args.logfile:
        parser.error('--debug requires use of --logfile')

    ap = None
    try:
        ap = AuthProgs(
            logfile=args.logfile,  # pylint: disable-msg=C0103
            configfile=args.configfile,
            configdir=args.configdir,
            debug=args.debug,
            keyname=args.keyname,
            silent=args.silent,
        )

        if args.dump_config:
            ap.dump_config()
            sys.exit(0)

        elif args.install_key:
            try:
                ap.install_key(args.install_key, args.authorized_keys)
                sys.stderr.write('Key installed successfully.\n')
                sys.exit(0)
            except InstallError as err:
                sys.stderr.write('Key install failed: {}'.format(err))
                sys.exit(1)

        elif args.run:
            ap.exec_command()
            sys.exit('authprogs command returned - should never happen.')
        else:
            parser.error('Not sure what to do. Consider --help')

    except SSHEnvironmentError as err:
        ap.log(
            'SSHEnvironmentError "{}"\n{}\n'.format(err, traceback.format_exc())
        )
        sys.exit('authprogs: {}'.format(err))
    except ConfigError as err:
        ap.log('ConfigError "{}"\n{}\n'.format(err, traceback.format_exc()))
        sys.exit('authprogs: {}'.format(err))
    except CommandRejected as err:
        sys.exit('authprogs: {}'.format(err))
    except Exception as err:
        if ap:
            ap.log(
                'Unexpected exception: {}\n{}\n'.format(
                    err, traceback.format_exc()
                )
            )
        else:
            sys.stderr.write(
                'Unexpected exception: {}\n{}\n'.format(
                    err, traceback.format_exc()
                )
            )
        sys.exit('authprogs experienced an unexpected exception.')


if __name__ == '__main__':
    sys.exit('This is a library only.')
