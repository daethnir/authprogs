from authprogs import authprogs
import argparse
import os
import sys
import glob

# Valid rsync binaries
# We don't want the client to pick a script
# that looks like rsync, we want it to be one
# of the official ones.

ALLOWED_RSYNC_BINARIES = ['/usr/bin/rsync', '/usr/local/bin/rsync']


class ParserError(RuntimeError):
    """Runtime rsync command line parser error."""

    pass


class ArgumentParserWrapper(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeError(message)


class RsyncValidator(object):
    """Rsync Parser class"""

    def __init__(self, authprogs):
        """AuthProgs rsync parser."""
        self.authprogs = authprogs
        self.logdebug = authprogs.logdebug
        if os.environ.get('AUTHPROGS_DEBUG_RSYNC_STDERR'):
            self.logdebug = lambda *x: sys.stderr.write(
                "DEBUG: {}\n".format(x[0])
            )
            authprogs.logdebug = lambda *x: sys.stderr.write(
                "DEBUG: {}\n".format(x[0])
            )

        self.raise_and_log_error = authprogs.raise_and_log_error
        self.log = authprogs.log
        self.parser = None
        self.boolarg_deny_default = {}
        self.boolarg_allow_default = {}

    def validate_rsync_args(self, args):
        """Verify the rsync args are well formed.

        Does not actually validate that they are appropriate,
        just that we got what we expect.
        """
        if not args.server:
            return False

        # First pathname for rsync server is always '.'
        if args.dot_path != '.':
            return

        # Possible future improvement: support filenames with spaces
        # or multiple files per request.
        #
        # The problem is choosing to support just one, or differentiating
        # the two.
        #
        # For example these:
        #   rsync remote:'my documents' :bin /tmp  # multiple files
        #   rsync remote:'my documents bin'  /tmp  # single file
        # produce the identical SSH_ORIGINAL_COMMAND
        #
        # For now, we simply require that spaces aren't used.
        if not args.local_path:
            self.logdebug('No local path!!')
            return False
        if args.extra:
            self.logdebug('spaces in local pathname not supported')
            return False
        return True

    def fixup_command(self, command, rule):
        """Fix up the command before we process."""

        # Verify binary is valid and replace with realpath version
        requested_bin = command.pop(0)
        rsync_bin = self.authprogs.valid_binary(
            requested_bin, ALLOWED_RSYNC_BINARIES
        )
        if not rsync_bin:
            self.logdebug(
                'skipping rsync processing, binary "{}"'
                ' not in approved list\n'.format(requested_bin)
            )
            return
        command.insert(0, rsync_bin)
        return True

    def rsync_globpaths(self, name):
        """Return paths of filename after doing rsync-like expansion."""
        paths = self.authprogs.globpaths(name, expanduser=True)
        return paths

    def expand_rule(self, rule):
        """Expand rule options and return new rule.

        Throws RuntimeError on problems.
        """
        if rule.get('allow_archive'):
            for expand in (
                'allow_recursive',
                'allow_links',
                'allow_perms',
                'allow_times',
                'allow_group',
                'allow_owner',
                'allow_devices',
                'allow_specials',
            ):
                if rule.get(expand) is False:
                    raise authprogs.ConfigError(
                        'Bad rule setting: has both allow_archive and {}=false'.format(
                            expand
                        )
                    )
                else:
                    rule[expand] = True

        return rule

    def validate_command(self, command, rule):
        """Determine if command matches the provided rsync rule.

        Return if not allowed.
        Return {'command': [command]} if acceptable.
        """

        rule = self.expand_rule(rule)

        if not self.fixup_command(command, rule):
            return

        orig_args = command[1:]
        args = self.parse_args(orig_args)

        self.logdebug("args: {}\n".format(args))
        if not self.validate_rsync_args(args):
            return

        # Annoying-to-handle options
        if not self.check_verbose(args, rule):
            return
        if not self.check_info(args, rule):
            return
        if not self.check_debug(args, rule):
            return

        # Good old default-denied booleans
        for arg, ruleoption in self.boolarg_deny_default.items():
            argname = arg.replace('-', '_')[2:]  # Get parser version
            if getattr(args, argname) and not self.feature_allowed(
                rule, ruleoption, default=False
            ):
                self.logdebug(
                    'Denied --{} when {} not enabled\n'.format(arg, ruleoption)
                )
                return

        # Good old default-allowed booleans
        for arg, ruleoption in self.boolarg_allow_default.items():
            argname = arg.replace('-', '_')[2:]  # Get parser version
            if getattr(args, argname) and not self.feature_allowed(
                rule, ruleoption, default=True
            ):
                self.logdebug(
                    'Denied --{} when {} not enabled\n'.format(arg, ruleoption)
                )
                return

        if args.delete:
            if not self.feature_allowed(rule, 'allow_delete', default=False):
                self.logdebug('Denied --delete when allow_delete not set\n')
                return
        if args.sender:
            if not self.feature_allowed(rule, 'allow_download', default=False):
                self.logdebug('Denied download when allow_download not set\n')
                return
        else:
            if not self.feature_allowed(rule, 'allow_upload', default=False):
                self.logdebug('Denied upload when allow_upload not set\n')
                return

        if not self.check_file_restrictions(args, rule):
            return

        return {'command': command}

    def check_file_restrictions(self, args, rule):
        """Check paths/path_startswith restrictions."""
        if 'paths' not in rule and 'path_startswith' not in rule:
            return True

        # If checking files or dirs (not yet implemented)
        # get the real paths, post globbing
        matching_paths = self.rsync_globpaths(args.local_path)
        if isinstance(matching_paths, list):
            unmatched = set(matching_paths)
        else:
            unmatched = set([matching_paths])
        self.logdebug(
            f'args.local_path {args.local_path}   and unmatched={unmatched}\n'
        )
        if not unmatched:
            self.logdebug(
                'Found no file match for {}\n'.format(args.local_path)
            )
            return

        if 'paths' in rule:
            for filename in list(unmatched):
                for path in rule['paths']:
                    if path.endswith('/'):
                        path = path[:-1]
                    if filename == path:
                        unmatched.remove(filename)
                        break

        if 'path_startswith' in rule:
            for filename in list(unmatched):
                for path_startswith in rule['path_startswith']:
                    if not path_startswith.endswith('/'):
                        path_startswith += '/'
                    if (filename + '/').startswith(path_startswith):
                        self.logdebug(
                            'path {} matches path_startswith {}\n'.format(
                                filename, path_startswith
                            )
                        )
                        unmatched.remove(filename)
                        break
        if unmatched:
            self.logdebug(
                'Following requested paths not matched: {}\n'.format(
                    ';'.join(unmatched)
                )
            )
            return
        else:
            self.logdebug('All paths matched: {}\n'.format(';'.join(unmatched)))
            return True

    def feature_allowed(self, rule, ruleparam, wanted=True, default=True):
        """Check a generic allow rule.

        Default is the value if the ruleparam is not set at all

        If value of ruleparam value matches wanted, return True
        if ruleparam value not present then if default matches wanted return True
        Else return False
        """
        paramvalue = rule.get(ruleparam, default)
        if paramvalue not in (True, False):
            self.raise_and_log_error(
                authprogs.ConfigError,
                'Unknown value "{}" for {}.'.format(paramvalue, ruleparam),
            )
        return paramvalue == wanted

    def check_verbose(self, args, rule):
        """Allow verbosity if request is at or below max verbosity."""
        if not args.verbose:
            return True
        verbosity_setting = rule.get('allow_verbose', True)
        if verbosity_setting in (True, False):
            return verbosity_setting
        return args.verbose <= verbosity_setting

    def check_info(self, args, rule):
        """Check --info verbosity."""
        if (
            not args.info
            or args.info.lower() == 'none'
            or rule.get('allow_info', True)
        ):
            return True
        return False

    def check_debug(self, args, rule):
        """Check --debug verbosity."""
        if (
            not args.debug
            or args.debug.lower() == 'none'
            or rule.get('allow_debug', True)
        ):
            return True
        return False

    def boolarg(self, *args, ruleoption=None, ruledefault=False, **kwargs):
        """Add a boolean arg to our self.parser."""
        self.parser.add_argument(*args, action='store_true', **kwargs)
        if ruleoption:
            longopt = [x for x in args if x.startswith('--')][0]
            if ruledefault:
                self.boolarg_allow_default[longopt] = ruleoption
            else:
                self.boolarg_deny_default[longopt] = ruleoption

    def parse_args(self, args):
        """Parse rsync args."""

        self.parser = ArgumentParserWrapper(add_help=False)

        self.boolarg('--server')
        self.boolarg('--sender')
        self.boolarg(
            '-c', '--checksum', ruleoption='allow_checksum', ruledefault=True
        )
        self.boolarg('-r', '--recursive', ruleoption='allow_recursive')
        self.boolarg('--del', dest='delete')
        self.boolarg('--delete', dest='delete')
        self.boolarg('--delete-after', dest='delete')
        self.boolarg('--delete-before', dest='delete')
        self.boolarg('--delete-delay', dest='delete')
        self.boolarg('--delete-during', dest='delete')
        self.boolarg('--delete-excluded', dest='delete')
        self.boolarg('--delete-missing-args', dest='delete')
        self.boolarg('-A', '--acls', ruleoption='allow_acls')
        self.boolarg('--devices', ruleoption='allow_devices')
        self.boolarg('-g', '--group', ruleoption='allow_group')
        self.boolarg('-l', '--links', ruleoption='allow_links')
        self.boolarg('-o', '--owner', ruleoption='allow_owner')
        self.boolarg('-p', '--perms', ruleoption='allow_perms')
        self.boolarg('--specials', ruleoption='allow_specials')
        self.boolarg(
            '-t', '--times', ruleoption='allow_times', ruledefault=True
        )
        self.boolarg('-D')

        self.parser.add_argument('-v', '--verbose', action='count', default=0)
        self.parser.add_argument('--info')
        self.parser.add_argument('--debug')

        self.parser.add_argument('dot_path', nargs='?')  # Should always be '.'
        self.parser.add_argument('local_path', nargs='?')  # Is the local path
        self.parser.add_argument('extra', nargs='*')  # extraneous arguments

        # Note: the '-e' argument is handled strangely in rsync.
        # On the server side it's a dot, followed by a select list of
        # client options, presumably for the purpose of logging. However
        # it is completely ignored by rsync server.
        # We could add support for that later, though it is of course
        # something the client could lie about to us.
        self.parser.add_argument('-e', '--rsh')

        try:
            rsync_args = self.parser.parse_args(args)
        except Exception as err:
            self.log('authprogs.rsync command parser failed: {}.\n'.format(err))
            raise ParserError('authprogs.rsync parser failure')

        # Post process arguments, e.g. expand some helper arguments, --no-foo
        if rsync_args.D:
            rsync_args.specials = True
            rsync_args.devices = True

        return rsync_args


if __name__ == '__main__':
    sys.exit('This is a library only.')
