#!/usr/bin/python
"""authprogs unit tests."""

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

import StringIO
from authprogs import authprogs
import unittest
import os


# pylint: disable-msg=C0103
def getap(client_ip='1.1.1.1', command='/bin/false',
          logfile=None, configfile=None, configdir=None,
          **ap_args):
    """Create a unittestable object."""

    # Force a valid SSH client and command, which may be overridden
    # in a test. Must override any that our shell already had!
    os.environ['SSH_CONNECTION'] = '%s 49725 127.0.0.1 22' % client_ip
    os.environ['SSH_CLIENT'] = '%s 49725 22' % client_ip

    os.environ.pop('SSH_ORIGINAL_COMMAND', None)
    if command:
        os.environ['SSH_ORIGINAL_COMMAND'] = command

    if not configfile:
        configfile = os.path.join(
                os.path.dirname(__file__),
                'testdata',
                'config.yaml')
    if not configdir:
        configdir = os.path.join(
                os.path.dirname(__file__),
                'testdata',
                'authprogs.d')

    ap = authprogs.AuthProgs(
            logfile=logfile,
            configdir=configdir,
            configfile=configfile,
            **ap_args)
    return ap


# pylint: disable-msg=R0904
class AuthProgsTests(unittest.TestCase):
    """AuthProgs unit test class."""

    def test_get_client_ip(self):
        """Verify we get the IP from the sshd env vars."""
        ap = getap()

        # Save environment for later
        environ = os.environ.copy()

        try:
            ap = getap()
            os.environ.clear()
            os.environ['SSH_CLIENT'] = '4.19.1.21 49725 22'
            self.assertEqual(ap.get_client_ip(), '4.19.1.21')

            ap = getap()
            os.environ.clear()
            os.environ['SSH_CONNECTION'] = '4.19.9.17 49725 127.0.0.1 22'
            self.assertEqual(ap.get_client_ip(), '4.19.9.17')

            ap = getap()
            os.environ.clear()
            os.environ['SSH_CONNECTION'] = '4.19.1.21 49725 22'
            os.environ['SSH_CLIENT'] = '4.19.9.17 49725 127.0.0.1 22'
            self.assertEqual(ap.get_client_ip(), '4.19.1.21')

            ap = getap()
            os.environ.clear()
            self.assertRaises(authprogs.SSHEnvironmentError, ap.get_client_ip)
        finally:
            # Reset environment
            os.environ = environ.copy()

    def test_single_bare_command(self):
        """Test that a single bare command works."""
        ap = getap('0.0.0.0', 'SINGLE')
        self.assertEqual(ap.find_match(),
                {'command': ['SINGLE']})

    def test_single_list_command(self):
        """Test that a single list command works."""
        ap = getap('0.0.0.1', 'SINGLE_LIST')
        self.assertEqual(ap.find_match(),
                {'command': ['SINGLE_LIST']})

    def test_multiple_list_command(self):
        """Test that multiple list commands work."""
        ap = getap('0.0.0.2', 'MULTIPLE_ONE', logfile='/tmp/out')
        self.assertEqual(ap.find_match(),
                {'command': ['MULTIPLE_ONE']})

        ap = getap('0.0.0.2', 'MULTIPLE_TWO')
        self.assertEqual(ap.find_match(),
                {'command': ['MULTIPLE_TWO']})

    def test_client_ip(self):
        """Verify we check client IP."""

        # Command valid from these IPs
        ap = getap('0.0.0.2', 'MULTIPLE_TWO')
        self.assertEqual(ap.find_match(),
                {'command': ['MULTIPLE_TWO']})
        ap = getap('1.1.1.1', 'MULTIPLE_TWO')
        self.assertEqual(ap.find_match(),
                {'command': ['MULTIPLE_TWO']})

        # Not valid from this one
        ap = getap('0.0.0.1', 'MULTIPLE_TWO')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_keyname_nospace(self):
        """Verify we reject keynames with spaces."""

        # No error raised
        dummy_ap = authprogs.AuthProgs(keyname='foobar')

        # Spaces triggers SSHEnvironmentError
        self.assertRaises(authprogs.Error,
                          authprogs.AuthProgs, keyname='foo bar')

    def test_keyname(self):
        """Verify we match keyname."""

        ap = getap('0.0.0.11', 'KEYTEST', keyname='foo')
        self.assertEqual(ap.find_match(), {'command': ['KEYTEST']})
        ap = getap('0.0.0.11', 'KEYTEST', keyname='bar')
        self.assertEqual(ap.find_match(), {'command': ['KEYTEST']})
        ap = getap('9.9.9.9', 'KEYTEST2', keyname='baz')
        self.assertEqual(ap.find_match(), {'command': ['KEYTEST2']})

        # Right IP, wrong keyname.
        ap = getap('0.0.0.11', 'KEYTEST', keyname='baz')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        # Right keyname, wrong IP.
        ap = getap('0.0.0.10', 'KEYTEST', keyname='foo')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_unrestricted_client_ip(self):
        """Verify we allow commands when no IP restriction is set."""

        # Allowed from anywhere
        ap = getap('9.9.9.9', 'NO_IP_RESTRICTIONS')
        self.assertEqual(ap.find_match(),
                {'command': ['NO_IP_RESTRICTIONS']})

    def test_command_with_args(self):
        """Verify we support args, and squash whitespace."""

        ap = getap('0.0.0.3', '/bin/echo Hello World')
        self.assertEqual(ap.find_match(),
                {'command': ['/bin/echo', 'Hello', 'World']})

    def test_command_bad_trailing_args(self):
        """Verify we don't allow trailing args unless specified."""

        ap = getap('0.0.0.3', '/bin/echo Hello World Peace!')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_command_with_trailing_args(self):
        """Verify we can support unspecified trailing args."""

        ap = getap('0.0.0.4', '/bin/echo Goodbye Cruel     World.')
        self.assertEqual(ap.find_match(),
                {'command': ['/bin/echo', 'Goodbye', 'Cruel', 'World.']})

    def test_pcre_command(self):
        """Verify we support PCRE regex-defined commands.."""

        for command in ['/bin/rm -r /var/tmp/foo',
                        '/bin/rm -rf /var/tmp/bar',
                        '/bin/rm -r -f /var/tmp/bar',
                        '/bin/rm     /var/tmp/../../etc/passwd',
                        '/bin/rm /var/tmp/qux']:
            ap = getap('0.0.0.5', command)
            self.assertEqual(ap.find_match(),
                             {'command': command.split()})

        for command in ['/bin/rm /tmp/file',
                        '/bin/rm /var/tmp/foo -f',
                        '/bin/rm /var/tmp/foo /etc/passwd']:
            ap = getap('0.0.0.5', command)
            self.assertRaises(authprogs.CommandRejected,
                              ap.find_match)

    def test_bad_scp_binary(self):
        """Verify we deny an unknown scp binary."""
        ap = getap('0.0.0.6', '/tmp/scp -d -f -- /etc/passwd')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_unrestricted_scp(self):
        """Verify unrestricted SCP works."""

        ap = getap('0.0.0.6', 'scp -f -- /etc/passwd')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-f', '--', '/etc/passwd']})

        ap = getap('0.0.0.6', 'scp -d -t -- /etc/passwd')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-d', '-t', '--', '/etc/passwd']})

    def test_explicitly_allowed_scp(self):
        """Verify explicitly allowed SCP works."""

        ap = getap('0.0.0.7', 'scp -d -f -- /etc/passwd')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-d', '-f', '--', '/etc/passwd']})

        ap = getap('0.0.0.7', 'scp -d -t -- /etc/passwd')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-d', '-t', '--', '/etc/passwd']})

    def test_unspecified_scp(self):
        """Verify SCP without any allow_ entries fails."""

        ap = getap('1.0.0.6', 'scp -f -- /etc/passwd')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        ap = getap('1.0.0.6', 'scp -d -t -- /etc/passwd')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_explicitly_denied_scp(self):
        """Verify explicitly denied SCP fails."""

        ap = getap('0.0.0.8', 'scp -d -f -- /etc/passwd')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        ap = getap('0.0.0.8', 'scp -d -t -- /etc/passwd')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_recursive_scp(self):
        """Verify recursive tests pass/fail as expected."""
        ap = getap('0.0.0.7', 'scp -r -t -- /tmp')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-r', '-t', '--', '/tmp']})

        ap = getap('0.0.0.9', 'scp -r -t -- /etc')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_permissions_scp(self):
        """Verify permissions tests pass/fail as expected."""

        ap = getap('0.0.0.7', 'scp -p -r -t -- /tmp')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-p', '-r', '-t', '--', '/tmp']})

        ap = getap('0.0.0.9', 'scp -p -r -t -- /etc')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_install_key(self):
        """Verify we can install a key into the authorized_keys file."""

        thefile = StringIO.StringIO()
        initial_contents = 'ssh-rsa AAAA foo@example.com'
        thefile.write(initial_contents)
        thefile.write('\n')

        keydata = 'ssh-rsa BBBB here@example.com'
        expected = ('%s\ncommand="/path/to/ap --run",no-port-forwarding %s\n'
                    % (initial_contents, keydata))

        ap = getap(authprogs_binary='/path/to/ap')
        ap.install_key_data(keydata, thefile)
        thefile.seek(0)
        self.assertEqual(expected, thefile.read())

    def test_install_key_with_logfile(self):
        """Verify we can install key with --logfile."""

        thefile = StringIO.StringIO()
        initial_contents = 'ssh-rsa AAAA foo@example.com'
        thefile.write(initial_contents)
        thefile.write('\n')

        keydata = 'ssh-rsa BBBB here@example.com'
        expected = ('%s\ncommand="/path/to/ap --run --logfile=/tmp/foo",'
                    'no-port-forwarding %s\n' %
                    (initial_contents, keydata))

        ap = getap(authprogs_binary='/path/to/ap', logfile='/tmp/foo')
        ap.install_key_data(keydata, thefile)
        thefile.seek(0)
        self.assertEqual(expected, thefile.read())

    def test_bad_environment(self):
        """Verify we raise SSHEnvironmentError when appropriate."""
        ap = getap('', '/bin/false')

        # No environment
        os.environ.pop('SSH_CLIENT')
        os.environ.pop('SSH_CONNECTION')
        self.assertRaises(authprogs.SSHEnvironmentError, ap.exec_command)

        # Bad env settings
        os.environ['SSH_CONNECTION'] = ''
        self.assertRaises(authprogs.SSHEnvironmentError, ap.exec_command)
        os.environ.pop('SSH_CONNECTION')
        os.environ['SSH_CLIENT'] = ''

        # No SSH command sent
        self.assertRaises(authprogs.SSHEnvironmentError, ap.exec_command)
        ap = getap('1.1.1.1', '')
        self.assertRaises(authprogs.SSHEnvironmentError, ap.exec_command)
        ap = getap('1.1.1.1', None)
        self.assertRaises(authprogs.SSHEnvironmentError, ap.exec_command)

    def test_install_key_duplicate(self):
        """Verify we don't install dups into the authorized_keys file."""

        thefile = StringIO.StringIO()
        initial_contents = ('command="" ssh-rsa AAAABBBBCCCCDD '
                            'foo@example.com\n')
        thefile.write(initial_contents)

        keydata = 'ssh-rsa AAAABBBBCCCCDD foo'

        ap = getap()
        self.assertRaises(authprogs.InstallError,
                          ap.install_key_data, keydata, thefile)

    def test_files_scp(self):
        """Verify we can restrict file/paths."""

        # Can download some files
        ap = getap('0.0.0.10', 'scp -f -- /etc/aliases')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-f', '--', '/etc/aliases']})
        ap = getap('0.0.0.10', 'scp -f -- /etc/passwd')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-f', '--', '/etc/passwd']})

        # Can't download this one
        ap = getap('0.0.0.10', 'scp -f -- /etc/passwd-')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        # Can't upload any of 'em
        ap = getap('0.0.0.10', 'scp -t -- /etc/passwd')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)
        ap = getap('0.0.0.10', 'scp -t -- /etc/aliases')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

        # Same uploads for different yaml doc w/ list specified
        # in alternate way
        ap = getap('1.0.0.10', 'scp -f -- /etc/group')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-f', '--', '/etc/group']})
        ap = getap('1.0.0.10', 'scp -f -- /etc/resolv.conf')
        self.assertEqual(ap.find_match(),
                {'command': ['scp', '-f', '--', '/etc/resolv.conf']})
        ap = getap('1.0.0.10', 'scp -f -- /etc/foo/')
        self.assertRaises(authprogs.CommandRejected, ap.find_match)

    def test_load(self):
        """Verify we can pull in configuration from file/dir."""

        # From config file
        ap = getap('0.0.0.4', '/bin/echo Goodbye')
        self.assertEqual(ap.find_match(),
                {'command': ['/bin/echo', 'Goodbye']})

        # From one file in config directory
        ap = getap('0.0.0.0', '100-config', logfile='/tmp/b')
        self.assertEqual(ap.find_match(),
                {'command': ['100-config']})

        # From another file in config directory
        ap = getap('0.0.0.0', '200-config')
        self.assertEqual(ap.find_match(),
                {'command': ['200-config']})

        # An intentionally-bad config file should throw
        # SSHEnvironmentError
        ap = getap('0.0.0.0', '200-config',
                      configfile=os.path.join(os.path.dirname(__file__),
                                              'testdata',
                                              'authprogs.d',
                                              '300-dir',
                                              'bad-file.yaml'))
        self.assertRaises(authprogs.Error, ap.find_match)

    def test_dotfiles_not_loaded(self):
        """Verify we don't load dotfiles in configdirs."""

        # Make sure we can match when using the .dotfile.yaml manually
        ap = getap('0.0.0.0', 'DOTFILE',
                      configfile=os.path.join(os.path.dirname(__file__),
                                              'testdata',
                                              'authprogs.d',
                                              '.dotfile.yaml'))
        self.assertEqual(ap.find_match(), {'command': ['DOTFILE']})

        ap = getap('0.0.0.0', 'DOTFILE',
                      configfdir=os.path.join(os.path.dirname(__file__),
                                              'testdata',
                                              'authprogs.d'))
        # Doesn't match now - it isn't read at all.
        self.assertRaises(authprogs.CommandRejected, ap.find_match)


if __name__ == '__main__':
    unittest.main()
