from authprogs import authprogs
import argparse
import os
import sys

# Valid scp binaries
# We don't want the client to pick a script
# that looks like scp, we want it to be one
# of the official ones.

ALLOWED_SCP_BINARIES = ['/usr/bin/scp', '/usr/local/bin/scp']


class ParserError(RuntimeError):
    """Runtime scp command line parser error."""

    pass


class ArgumentParserWrapper(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeError(message)


class ScpValidator(object):
    """Scp Parser class"""

    def __init__(self, authprogs):
        """AuthProgs scp parser."""
        self.authprogs = authprogs
        self.logdebug = authprogs.logdebug
        if os.environ.get('AUTHPROGS_DEBUG_SCP_STDERR'):
            self.logdebug = lambda *x: sys.stderr.write(
                "DEBUG: {}\n".format(x[0])
            )
            authprogs.logdebug = lambda *x: sys.stderr.write(
                "DEBUG: {}\n".format(x[0])
            )

        self.raise_and_log_error = authprogs.raise_and_log_error
        self.log = authprogs.log
        self.parser = None

    def fixup_command(self, command, rule):
        """Fix up the command before we process."""

        # Verify binary is valid and replace with realpath version
        requested_bin = command.pop(0)
        scp_bin = self.authprogs.valid_binary(
            requested_bin, ALLOWED_SCP_BINARIES
        )
        if not scp_bin:
            self.logdebug(
                'skipping scp processing, binary "{}"'
                ' not in approved list\n'.format(requested_bin)
            )
            return
        command.insert(0, scp_bin)
        return command

    def validate_command(self, command, rule):
        """Determine if command matches the provided scp rule.

        Return None if not allowed.
        Return {'command': [command]} if acceptable.
        """
        orig_list = command[:]

        command = self.fixup_command(command, rule)
        if not command:
            return

        args = self.parse_args(command[1:])
        if len(args.extra) != 1:
            self.log('scp cmdline parsing expecting exactly one path.')
            return

        if args.authprogs_reject:
            return
        filepath = args.extra[0]

        if args.download and args.upload:
            self.logdebug(
                'client scp requested upload and download'
                ' simultaneously - rejecting.'
            )
            return
        if not (args.download or args.upload):
            self.logdebug(
                'client scp requested neither upload nor download'
                ' - rejecting.'
            )

        if args.download:
            if not rule.get('allow_download'):
                self.logdebug('scp denied - downloading forbidden.\n')
                return

        if args.upload:
            if not rule.get('allow_upload'):
                self.log('scp denied - uploading forbidden.\n')
                return

        if 'allow_recursion' in rule:
            self.log(
                'WARNING: deprecated option "allow_recursion" set in rule.'
                ' Update to allow_recursive.\n'
            )
            vals = set(
                [rule.get('allow_recursive'), rule.get('allow_recursion')]
            )
            if True in vals and False in vals:
                self.log(
                    'CRITICAL: both allow_recursive and allow_recursion are set,'
                    ' but to different values. Skipping bad rule.\n'
                )
                return
            if 'allow_recursive' not in rule:
                rule['allow_recursive'] = rule['allow_recursion']
        if args.recursive:
            if not rule.get('allow_recursive'):
                self.log('scp denied - recursive transfers forbidden.\n')
                return

        if args.permissions:
            if not rule.get('allow_permissions', 'true'):
                self.log('scp denied - set/getting permissions forbidden.\n')
                return

        if 'files' in rule:
            self.log(
                'WARNING: deprecated option "files" set in rule.'
                ' Update to paths.\n'
            )
            if 'paths' in rule:
                rule['paths'].extend(rule['files'])
            else:
                rule['paths'] = rule['files']
        if rule.get('paths'):
            files = rule.get('paths')
            if not isinstance(files, list):
                files = [files]
            if filepath not in files:
                self.log(
                    'scp denied - file "{}" - not in approved '
                    'list {}\n'.format(filepath, files)
                )
                return

        # Allow it!
        return {'command': command}

    def parse_args(self, args):
        """Parse scp args."""

        self.parser = ArgumentParserWrapper(add_help=False)

        self.parser.add_argument(
            '-d', action='store_true', dest='targetshouldbedirectory'
        )
        self.parser.add_argument('-f', action='store_true', dest='download')
        self.parser.add_argument('-t', action='store_true', dest='upload')
        self.parser.add_argument('-r', action='store_true', dest='recursive')
        self.parser.add_argument('-p', action='store_true', dest='permissions')
        self.parser.add_argument('-v', action='store_true', dest='verbose')
        self.parser.add_argument(
            '-S', action='store_true', dest='authprogs_reject'
        )
        self.parser.add_argument('extra', nargs='*')

        try:
            scp_args = self.parser.parse_args(args)
        except Exception as err:
            self.log('authprogs.scp command parser failed: {}.\n'.format(err))
            raise ParserError('authprogs.scp parser failure: {} '.format(err))
        return scp_args
