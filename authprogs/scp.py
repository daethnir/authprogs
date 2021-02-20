from authprogs import authprogs
import argparse
import shutil
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

    def validate_command(self, original_command_list, rule):
        """Determine if command matches the provided rsync rule.

        Return None if not allowed.
        Return {'command': [command]} if acceptable.
        """

        # TODO: validate binary
        #if not self.fixup_command(command, rule):
        #    return

        #orig_args = command[1:]
        #args = self.parse_args(orig_args)


        orig_list = original_command_list[:]
        binary = orig_list.pop(0)
        allowed_binaries = ['scp', '/usr/bin/scp']
        if binary not in allowed_binaries:
            self.logdebug(
                'skipping scp processing - binary "{}" '
                'not in approved list.\n'.format(binary)
            )
            return

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
        return {'command': original_command_list}
