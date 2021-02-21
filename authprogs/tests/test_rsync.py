#!/usr/bin/python3
# vim: set ts=4 et
"""authprogs rsync unit tests."""

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


from authprogs import authprogs
from authprogs import rsync
from authprogs.tests.test_authprogs import getap
import io
import unittest
import os
import sys


# pylint: disable-msg=R0904
class RsyncTests(unittest.TestCase):
    """AuthProgs unit test class."""

    def setUp(self):
        """setup."""
        # Inelegant and FHS-dependent way to get to / so
        # we can do wildcard path checks. Sorry.
        if not getattr(self, '__origdir', None):
            self.__origdir = os.path.realpath(os.curdir)
        os.chdir('/')

    def tearDown(self):
        os.chdir(self.__origdir)

    def getap(self, ip, resultstr, skip_binary_check=True):
        """Get an Authprogs object.

        If skip_binary_check is set (default) then don't verify
        that argv[0] is a valid rsync binary.
        """
        ap = getap(ip, resultstr)
        if skip_binary_check:
            ap.valid_binary = lambda *x: 'rsync'
        return ap

    def command_rejected(self, ip, result, apmutate=None):
        """Try an rsync command and expect failure.

        Results is a string or an array, and is split or
        ' '.joined as appropriate.
        """
        try:
            self.command_allowed(ip, result, apmutate=apmutate)
        except (authprogs.CommandRejected, AssertionError):
            # The command_allowed failed - good!
            return
        else:
            raise AssertionError(
                '"{}" => "{}" did not fail as needed'.format(ip, result)
            )

    def command_allowed(self, ip, result, apmutate=None):
        """Try an rsync command and expect success.

        Results is a string or an array, and is split or
        ' '.joined as appropriate.
        """
        if isinstance(result, str):
            resultstr = result
            resultarr = result.split()
        else:
            resultarr = result
            ' '.join(resultstr)

        ap = self.getap(ip, resultstr)
        if apmutate:
            ap = apmutate(ap)
        self.assertEqual(ap.find_match(), {'command': resultarr})

    def test_usage_minimal(self):
        """Verify some minimal usage checks."""

        # Verify hella minimal one parses
        self.command_allowed('0.1.0.0', 'rsync --server . /dst')

        # but without --server, or exactly 2 paths, we fail
        self.command_rejected('0.1.0.0', 'rsync . /dst')
        self.command_rejected('0.1.0.0', 'rsync --server .')
        self.command_rejected('0.1.0.0', 'rsync --server . /dst extra')

        # Unknown argument
        ap = self.getap('0.1.0.0', 'rsync --server --barnacle . /dst')
        self.assertRaises(rsync.ParserError, ap.find_match)

    def test_rsh_command(self):
        """Verify we ignore the -e option value.

        -e on server takes a string that is ignored, but to the human
        eye it looks like it should be parsed. What the rsync
        developers were thinking, I don't know.
        """
        # TODO: verify that if we have -e.r it does not set recursive mode
        for ebits in ('e.', 'e.r', 've.', 've.r', 've.$%^&*'):
            self.command_allowed(
                '0.1.0.0', 'rsync --server -{} . /dst'.format(ebits)
            )

    def test_verbose_again(self):
        """Verify we handle verbose level."""
        for ip in ('0.1.0.0', '0.1.0.1'):
            self.command_allowed(ip, 'rsync --server -v . /dst')
            self.command_allowed(ip, 'rsync --server -vv . /dst')

        self.command_rejected('0.1.0.2', 'rsync --server -v . dst')

    def test_bad_rsync_binary(self):
        """Verify we deny an unknown rsync binary."""
        cmd = 'rsync --server -vv . /dst'

        ap = self.getap('0.1.0.0', cmd)
        ap = self.getap('0.1.0.0', cmd, skip_binary_check=False)
        ap._whichbin = lambda x: None
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        ap = self.getap('0.1.0.0', cmd, skip_binary_check=False)
        ap._whichbin = lambda x: '/home/wbagg/bin/rsync'
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        for allowed in rsync.ALLOWED_RSYNC_BINARIES:
            ap = getap('0.1.0.0', cmd)
            ap._whichbin = lambda x: allowed
            self.assertEqual(
                ap.find_match(),
                {'command': [allowed, '--server', '-vv', '.', '/dst']},
            )

    def test_unrestricted_rsync(self):
        """Verify we allow unrestricted rsync."""
        # Try a few generic commands. Verify parsing
        # works as expected.
        ap = self.getap('0.1.0.0', 'rsync --server -e.LsfxC . /etc/group')
        self.assertEqual(
            ap.find_match(),
            {'command': ['rsync', '--server', '-e.LsfxC', '.', '/etc/group']},
        )

        ap = self.getap(
            '0.1.0.0', 'rsync --server --sender -e.LsfxC . /etc/group'
        )
        self.assertEqual(
            ap.find_match(),
            {
                'command': [
                    'rsync',
                    '--server',
                    '--sender',
                    '-e.LsfxC',
                    '.',
                    '/etc/group',
                ]
            },
        )

    def test_verbose(self):
        """Verify we handle verbosity."""

        # Not specified
        self.command_allowed('0.1.0.0', 'rsync --server -e.LsfxC . /etc/group')
        self.command_allowed('0.1.0.0', 'rsync --server -ve.LsfxC . /etc/group')

        # verbose allowed
        self.command_allowed('0.1.0.1', 'rsync --server -e.LsfxC . /etc/group')
        self.command_allowed('0.1.0.1', 'rsync --server -ve.LsfxC . /etc/group')

        # verbose would be rejected, but not supplied
        self.command_allowed('0.1.0.22', 'rsync --server -e.LsfxC . /etc/group')
        self.command_allowed(
            '0.1.0.22', 'rsync --server --debug=nOnE -e.LsfxC . /etc/group'
        )
        self.command_allowed(
            '0.1.0.22', 'rsync --server --info=nOnE -e.LsfxC . /etc/group'
        )
        self.command_allowed(
            '0.1.0.22',
            'rsync --server --info=none --debug=nOnE -e.LsfxC . /etc/group',
        )

        # verbose supplied, must reject
        self.command_rejected(
            '0.1.0.22', 'rsync --server -ve.LsfxC . /etc/group'
        )
        self.command_rejected(
            '0.1.0.22', 'rsync --server -vvve.LsfxC . /etc/group'
        )
        self.command_rejected(
            '0.1.0.22', 'rsync --server -v -vvve.LsfxC . /etc/group'
        )

        # --info supplied, reject
        self.command_rejected(
            '0.1.0.23', 'rsync --server --info All -e.LsfxC . /etc/group'
        )

        # --debug supplied, reject
        self.command_rejected(
            '0.1.0.24', 'rsync --server --debug=All -e.LsfxC . /etc/group'
        )

        # --debug and --info supplied, check both rules
        self.command_rejected(
            '0.1.0.23',
            'rsync --server --debug=acl --info all  -e.LsfxC . /etc/group',
        )
        self.command_rejected(
            '0.1.0.24',
            'rsync --server --debug=acl --info all  -e.LsfxC . /etc/group',
        )

        # Count the -v's - any up to 2 is ok
        self.command_allowed('0.1.0.25', 'rsync --server -e.LsfxC . /etc/group')
        self.command_allowed(
            '0.1.0.25', 'rsync --server -ve.LsfxC . /etc/group'
        )
        self.command_allowed(
            '0.1.0.25', 'rsync --server -vve.LsfxC . /etc/group'
        )
        self.command_rejected(
            '0.1.0.25', 'rsync --server -vvve.LsfxC . /etc/group'
        )

    def test_limit_download_upload(self):
        """Verify we can selectively prevent download or upload."""
        # Test download
        self.command_allowed(
            '0.1.0.3', 'rsync --server          -e.LsfxC . /etc/group'
        )
        self.command_rejected(
            '0.1.0.3', 'rsync --server --sender -e.LsfxC . /etc/group'
        )

        # Test upload
        self.command_allowed(
            '0.1.0.4', 'rsync --server --sender -e.LsfxC . /etc/group'
        )
        self.command_rejected(
            '0.1.0.4', 'rsync --server          -e.LsfxC . /etc/group'
        )

        # A rule that makes no sense - both download and upload rejected
        self.command_rejected(
            '0.1.0.5', 'rsync --server --sender -e.LsfxC . /etc/group'
        )
        self.command_rejected(
            '0.1.0.5', 'rsync --server          -e.LsfxC . /etc/group'
        )

    def test_limit_recursive(self):
        """Verify we can selectively prevent recusive file transfer."""
        self.command_allowed('0.1.0.6', 'rsync --server    -e.LsfxC . /tmp/')
        self.command_rejected('0.1.0.6', 'rsync --server -r -e.LsfxC . /tmp/')
        self.command_rejected('0.1.0.6', 'rsync --server -re.LsfxC . /tmp/')

    def test_archive(self):
        """Verify we can support --archive flag."""
        self.command_allowed('0.1.0.26', 'rsync --server -e.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -le.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -oe.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -ge.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -pe.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -te.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -re.iLsfxC . /tmp/')
        self.command_allowed('0.1.0.26', 'rsync --server -De.iLsfxC . /tmp/')
        self.command_allowed(
            '0.1.0.26', 'rsync --server -logDtpre.iLsfxC . /tmp/'
        )
        self.command_allowed('0.1.0.26', 'rsync --server -tge.iLsfxC . /tmp')
        self.command_allowed(
            '0.1.0.26', 'rsync --server --devices --specials -oge.iLsfxC . /tmp'
        )
        self.command_allowed('0.1.0.26', 'rsync --server -oge.iLsfxC . /tmp')

        # Combining allow_archive and other allow_ expansions is always bad
        self.command_allowed('0.1.0.26', 'rsync --server -e. . /tmp/')
        ap = self.getap('0.1.0.27', 'rsync --server -e. . /dst')
        # self.command_rejected('0.1.0.27', 'rsync --server -e.iLsfxC . /tmp/')
        self.assertRaises(authprogs.ConfigError, ap.find_match)

    def test_recursive_and_delete(self):
        """Verify we can support delete and recusive file transfer."""
        self.command_allowed('0.1.0.8', 'rsync --server -re.iLsfxC . /tmp/')
        self.command_rejected(
            '0.1.0.8', 'rsync --delete --server -re.LsfxC . /tmp/'
        )

        self.command_allowed('0.1.0.9', 'rsync --server -re.iLsfxC . /tmp/')
        delete_options = (
            '--del',
            '--delete',
            '--delete-before',
            '--delete-during',
            '--delete-delay',
            '--delete-after',
            '--delete-excluded',
            '--delete-missing-args',
        )
        for opt in delete_options:
            self.command_allowed(
                '0.1.0.9', 'rsync {} --server -re.LsfxC . /tmp/'.format(opt)
            )

    def _fake_os_path_abspath(self, name):
        """mock os.path.abspath, always assumes wbagg home dir"""
        wbagg_home = '/home/wbagg/'
        if name[0] not in ('/', '~'):
            name = wbagg_home + name

        # strip trailing slashes like abspath does
        while name.endswith('/'):
            name = name[:-1]
        return name or '/'

    def _fake_os_path_expanduser(self, name):
        """mock os.path.expanduser"""
        wbagg_home = '/home/wbagg/'
        groot_home = '/home/groot/'
        if name == '~' or name.startswith('~/'):
            return wbagg_home + name[2:]
        if name.startswith('~wbagg'):
            return wbagg_home + name[7:]
        if name.startswith('~groot'):
            return groot_home + name[7:]
        return name

    def _fake_glob(self, name):
        """mock glob.glob."""
        answers = {
            '/globs/subs/dir[34]': ['/globs/subs/dir3', '/globs/subs/dir4'],
            '/globs/subs/dir*': [
                '/globs/subs/dir3',
                '/globs/subs/dir4',
                '/globs/subs/dir5]',
            ],
            '/globs/dir*': ['/globs/dir1', '/globs/dir2', '/globs/directory'],
            '/globs/dir?': ['/globs/dir1', '/globs/dir2'],
        }
        # Return fake one or original
        return answers.get(name, [name])

    def _fake_os_path_realpath(self, name):
        """mock os.path.realpath"""
        answers = {
            '/etc/mtab': '/proc/mounts',  # file
            '/var/run/foo.pid': '/run/foo.pid',  # directory
            '/etc/localtime': '/usr/share/zoneinfo/Etc/UTC',
        }
        # Strip trailing slash and return fake
        # one, original, or homedir + original
        name = name.rstrip('/')
        if name in answers:
            return answers[name]
        if not name.startswith('/'):
            return '/home/wbagg/' + name
        return name

    def _ap_fs_mutater(self, ap):
        """Mock all filesystem calls.

        Allows us to do unit tests without real filesystem dependencies.
        """
        ap._glob = self._fake_glob
        ap._os_path_expanduser = self._fake_os_path_expanduser
        ap._os_path_realpath = self._fake_os_path_realpath
        ap._os_path_abspath = self._fake_os_path_abspath
        return ap

    def test_buncha_bools(self):
        """Verify a bunch of booleans."""
        bools_default_denied = {
            11: ['--devices'],
            12: ['--specials'],
            13: ['--acls', '-A'],
            14: ['--group', '-g'],
            15: ['--links', '-l'],
            16: ['--owner', '-o'],
            17: ['--perms', '-p'],
            21: [
                '--del',
                '--delete',
                '--delete-after',
                '--delete-before',
                '--delete-delay',
                '--delete-during',
                '--delete-excluded',
                '--delete-missing-args',
            ],
            19: ['--recursive', '-r'],
        }
        bools_default_allowed = {
            18: ['--times', '-t'],
            20: ['--checksum', '-c'],
        }
        for num, options in bools_default_denied.items():
            for option in options:
                command = 'rsync {} --server -vv . /dst'.format(option)
                self.command_rejected('0.1.0.10', command)
                self.command_allowed('0.1.0.{}'.format(num), command)

        for num, options in bools_default_allowed.items():
            for option in options:
                command = 'rsync {} --server -vv . /dst'.format(option)
                self.command_allowed('0.1.0.10', command)
                self.command_rejected('0.1.0.{}'.format(num), command)

    def test_limit_restricted_path(self):
        """Verify we can restrict path."""
        success = (
            # Explicit file test
            '/etc/group',
            '/home/wbagg/.profile',
            ###########################################
            ## May have support for realpath in future.
            ## But not today....
            ## symlinks
            ##  /var/run => /run/
            #'/var/run/foo.pid', # symlink file
            ##  /etc/localtime => /usr/share/zoneinfo/Etc/UTC
            #'/etc/localtime', # symlink file in path_startswith
            # globs
            '/globs/subs/dir[34]',
            '/globs/dir?',
            # User expansion
            '.profile',
            '~/.profile',
            '~groot/bin/authprogs',
            '~wbagg/.profile',
            # Subdir
            '/data/lhc/2008-09-10/dipoles.csv',
            '/proc/sys',  # path_startswith test
            '/proc/sys/net',  # path_startswith test
            '/proc/sys/net/core/somaxconn',  # path_startswith test
            # Test trailing slashes
            '/var',
            '/var/',
            '/tmp',
            '/tmp/',
        )
        for _ in success:
            self.command_allowed(
                '0.1.0.7',
                'rsync --server  -e.LsfxC . {}'.format(_),
                apmutate=self._ap_fs_mutater,
            )

        failure = (
            # prefix match attempts
            '/etc/groupies',  # doesn't match /etc/group file
            '/home/wbagg',  # doesn't match /home/wbagg/.profile file
            '/home/wbagg/.profile/foo',  # doesn't match /home/wbagg/.profile file
            '/data/lhc.old',  # doesn't match /data/lhc path_startswith
            '/proc/system',  # doesn't match /proc/sys path_startswith
            '/tmperment',  # trailing charts after /tmp
            '/variable',  # trailing charts after /var
            # globs
            '/globs/dir*',  # matches too many files
            '/globs/subs/dir*',  # matches too many files
            # doesn't even vaguely match anything
            '/no/such/dir',
            '/etc/no_such_etc_file',
            # user expansion
            '~wbagg/.profile-',  # doesn't match /home/wbagg/.profile file
            '~groot/bin/authprogs-',  # doesn't match /home/groot/bin/authprogs
            # in a path, not a path_startswith
            '/tmp/foo',
            '/tmp/foo/',
            '/var/bar',
            '/var/bar/',
        )

        for _ in failure:
            self.command_rejected(
                '0.1.0.7',
                'rsync --server  -e.LsfxC . {}'.format(_),
                apmutate=self._ap_fs_mutater,
            )


if __name__ == '__main__':
    unittest.main()
