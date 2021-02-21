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
    """Runtime rsync command line parser error."""

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
        scp_bin = self.authprogs.valid_binary(requested_bin, ALLOWED_SCP_BINARIES)
        if not scp_bin:
            self.logdebug(
                'skipping scp processing, binary "{}"'
                ' not in approved list\n'.format(requested_bin))
            return
        command.insert(0, scp_bin)
        return command

    def validate_command(self, command, rule):
        """Determine if command matches the provided rsync rule.

        Return None if not allowed.
        Return {'command': [command]} if acceptable.
        """
        orig_list = command[:]

        command = self.fixup_command(command, rule)
        if not command:
            return

        #orig_args = command[1:]
        #args = self.parse_args(orig_args)

        binary = orig_list.pop(0)
        filepath = orig_list.pop()
        arguments = orig_list

        if '-f' in arguments:
            if not rule.get('allow_download'):
                self.logdebug('scp denied - downloading forbidden.\n')
                return

        if '-t' in arguments:
            if not rule.get('allow_upload'):
                self.log('scp denied - uploading forbidden.\n')
                return

        if '-r' in arguments:
            if not rule.get('allow_recursion'):
                self.log('scp denied - recursive transfers forbidden.\n')
                return

        if '-p' in arguments:
            if not rule.get('allow_permissions', 'true'):
                self.log('scp denied - set/getting permissions forbidden.\n')
                return

        if rule.get('files'):
            files = rule.get('files')
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
