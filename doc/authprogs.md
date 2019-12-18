authprogs(1) -- SSH command authenticator
=========================================

## SYNOPSIS

`authprogs --run [options]`

`authprogs --install_key  [options]`

`authprogs --dump_config  [options]`

`authprogs --help`

## DESCRIPTION

`authprogs` is an SSH command authenticator. It is invoked on
an ssh server and decides if the command requested by the
ssh client should be run or rejected based on logic in the `authprogs`
configuration file.

Passwordless SSH using ssh identies or pubkeys can enable all
sorts of wonderful automation, for example running unattended
batch jobs, slurping down backups, or pushing out code.
Unfortunately a key, once trusted, is allowed by default to run
anything on that system, not just the small set of commands you
actually need. If the key is compromised, you are at risk of a
security breach. This could be catastrophic, for example if the
access is to the root account.

Authprogs is run on the SSH server and compares the requested
command against the `authprogs` configuration file/files. This
enables `authprogs` to make intelligent decisions based on things
such as the command itself, the SSH key that was used, the
client IP, and such.

`authprogs` is enabled by using the `command=` option in the
`authorized_keys` file.

## KEY INSTALLATION

You can install your ssh identities/pubkeys manually, or allow authprogs to do the work for you.

## MANUAL KEY INSTALLATION

You need to set up your `~/.ssh/authorized_keys` file to force
invocation of authprogs for the key or keys you wish to protect.

A line of an unrestricted `authorized_key` entry might look like this:

    ssh-rsa AAAAB3NzaC1yc2E.....OgQ7Pm1X8= user@example.com

When setting up this key to use authprogs, you add a `command=` option
to the very beginning of that line that points to the location where
authprogs lives. For example if authprogs is in /usr/bin/authprogs,
you would use this:

    command="/usr/bin/authprogs --run" ssh-rsa AAAAB3NzaC1yc2E.....OgQ7Pm1X8= user@example.com

You must include `--run` to let authprogs know it is running in SSH command mode.

Authprogs has other commandline options you may wish to include
as well, for example

    command="/usr/bin/authprogs --keyname=backups --run" ssh-rsa AAAA...Pm1X8= user@example.com

Lastly, if you wish, ssh offers a number of other helpful
restrictions you may wish to include that are separate from
authprogs. These can be appended right after (or before) the
command="" section if you wish.

    command="/usr/bin/authprogs --run",no-port-forwarding,no-pty ssh-rsa AAAA..Pm1X8= user@example.com

See the sshd(8) man page for more information about allowed
`authorized_keys` configuration options.

## AUTOMATED KEY INSTALLATION

Authprogs is capable of adding your key to your `authorized_keys`
file (`~/.ssh/authorized_keys` by default) programatically. It
also disableds ssh port forwarding by default for this key (a
sensible default for most batch jobs.)

authprogs will refuse to install a key that is already present
in the `authorized_keys` file.

For example the following

    authprogs --install_key /path/to/backups_key.pub --keyname=backups

would cause the following line to be added to your
`~/.ssh/authorized_keys` file:

    command="/usr/bin/authprogs --keyname backups --run",no-port-forwarding ssh-rsa AAAA..Pm1X8= user@example.com

## RUN MODE OPTIONS

Authprogs can run in several modes, depending on which of these
command line switches you provide.

* `--run`:
   Act in run mode, as from an `authorized_keys` file.

* `--install_key filename`:
  Install the key contained in the named file into your `authorized_keys` file.

* `--dump_config`:
  Dump the configuration in a python-style view. Helpful only for debugging.

* `--help`:
  Show help information

## OTHER OPTIONS

The folowing options may apply to multiple run modes, as appropriate.

* `--keyname key_name`:
    This option 'names' the key, for help in
    crafting your rules. Since an account may have multiple keys
    allowed, this helps us differentiate which one was used so we
    can make sensible choices.

    In run mode, this specifies which name is used when
    matching in the configuration, e.g.

        command="/usr/bin/authprogs --keyname backups --run" ...

    In key installation mode, this adds the `--keyname` option to
    the `authorized_keys` entry.

    `key_name` may contain no whitespace.

* `--configfile`:
    Specifies the authprogs configuration file to read.
    Defaults to `~/.ssh/authprogs.yaml`.

    In key installation mode, this adds the `--configfile`
    option to the `authorized_keys` entry.

* `--configdir`:
     Specifies the authprogs configuration, in which
     multiple configuration files can be found.
     Defaults to `~/.ssh/authprogs.d` if present.

     Files in the configuration directory are read
     as rules in filename order. See CONFIGURATION
     for more info.


## LIMITATIONS

Commands are executed via fork/exec, and are not processed through
the shell. This means you cannot have multiple commands separated
by semicolons, pipelines, redirections, backticks, shell builtins,
wildcards, variables, etc.

Also, you cannot have spaces in any arguments your command runs.
This is because the SSH server takes the command that was specified
by the client and squashes it into the `SSH_ORIGINAL_COMMAND`
variable. By doing this it makes it impossible for us to know
what spaces in `SSH_ORIGINAL_COMAND` were between arguments and which
were part of arguments.

Here are some commands that would not work through authprogs:

* `ssh host "rm /tmp/foo; touch /tmp/success"`
* `ssh host "rm /tmp/*.html"`
* `ssh host "cut -d: -f 1 /etc/passwd > /tmp/users"`
* `ssh host "touch '/tmp/file with spaces'"`
* `ssh host "for file in /tmp/*.html; do w3m -dump $file > $file.txt; done"`

You can work around these limitations by writing a shell script that
does what you need and calling that from authprogs, rather than attempting
to run complicated commandlines via ssh directly.

## CONFIGURATION FILES

authprogs rules are maintained in one or more configuration files
in YAML format. 

The rules allow you to decide whether the client's command should be run
based on criteria such as the command itself, the client IP address, and
ssh key in use.

Rules can be read from a single file (`~/.ssh/authprogs.yaml` by default)
or by putting files in a configuration directory (`~/.ssh/authprogs.d`).
The configuration directory method is most useful when
you want to be able to easily add or remove rules without manually
editing a single configuration file, such as when installing rules
via your configuration tool of choice.

All the authprogs configuration files are concatenated
together into one large yaml document which is then processed.
The files are concatenated in the following order:

* `~/.ssh/authprogs.yaml`, if present
* files in `~/.ssh/authprogs.d/` directory, in asciibetical order

Dotfiles contained in a configuration directory are ignored.
The configuration directory is not recursed; only those files directly
contained are processed.

Each rule in the configuration file/files is tested in order and once
a match is found, processing stops and the command is run.

Rules are made of rule selection options (e.g. client IP address)
and subrules (e.g. a list of allowed commands). All pieces must
match for the command to be run.

The general format of a rule is as follows:

    # First rule
    -
      # Selection options
      #
      # All must match or we stop processing this rule.
      selection_option_1: value
      selection_option_2: value

      # The allow block, aka subrules
      #
      # This lets us group a bunch of possible commands
      # into one rule. Otherwise we'd need a bunch of
      # rules where you repeat selection options.

      allow:
        -
          rule_type: value
          rule_param_1: value
          rule_param_2: value
        -
          rule_type: value2
          rule_param_1: value
          rule_param_2: value

    # Next rule
    -
      selection_option_3: value
    ...

Some of the keys take single arguments, while others may take lists.
See the definition of each to understand the values it accepts.

## RULE SELECTION OPTIONS

These configuration options apply to the entire rule, and help
you limit under what conditions the rule matches.

* from: This is a single value or list of values that define what SSH client
IP addresses are allowed to match this rule. The client IP address
is gleaned by environment variables set by the SSH server. Any from value
may be an IP address or a CIDR network.

Examples:

    -
      from: 192.168.1.5
      ...

    -
      from: [192.168.0.1, 10.0.0.3]
      ...

    -
      from:
        - 192.168.0.0/24
        - 10.10.0.3
      ...

* keynames:  This is a single value or list of values that define which
SSH pubkeys are allowed to match this rule.  The keyname
is specified by the `--keyname foo` parameter in the
authprogs command line in the entry in `authorized_keys`.

Examples:


    -
      keynames: backups
      ...

    -
      keynames: [repo_push, repo_pull]
      ...

    -
      keynames:
        - repo_push
        - repo_pull
      ...

## ALLOW SUBRULE SECTION

The allow section of a rule is a single subrule or list of subrules.

Subrules can be simple, for example the explicit command match, or be
more program-aware such as scp support. You specify which kind of
subrule you want with the `rule_type` option:

    -
      allow:
        -
          rule_type: command
          command: /bin/touch /tmp/timestamp
        -
          command: /bin/rm /tmp/bar
        -
          rule_type: scp
          allow_upload: true
    ...

See the separate subrules sections below for how to craft each type.

## COMMAND SUBRULES

This section applies if `rule_type` is set to `command` or is not
present at all.

The command requested by the client is compared to the command
listed in the rule. (Spaces are squashed together.) If it matches,
then the command is run.

Note that the command must be *exactly* the same; authprogs is not
aware of arguments supported by a comamnd, so it cannot realize that
`"ls -la"` and `"ls -a -l"` and `"ls -al"` and `"ls -l -a"` are all the
same. You can list multiple commands to allow you to accept
variants of a command if necessary.

The simplest configuration looks like this:

    -
      allow:
        command: /bin/true

Or you can provide a list of commands:

    -
      allow:
        - command: /bin/true
        - command: /bin/false

A number of optional settings can tweak how command matching
is performed.

* `allow_trailing_args: true`:  This setting allows you to specify a
    partial command that will match as long as the command requested
    by the client is the same or longer.  This allows you to avoid
    listing every variant of a command that the client may wish to run.

    Examples:

      -
        allow:
          -
            command: /bin/echo
            allow_trailing_args: true
          -
            command: /bin/ls
            allow_trailing_args: true
          -
            command: /bin/rm -i
            allow_trailing_args: true

* `pcre_match: true`:  Compare the command using pcre regular expressions,
    rather than doing an explicit match character by character. The regex
    is *not* anchored at the beginning nor end of the string, so if you
    wish to anchor it is your responsibility to do so.

    Caution: never underestimate the sneakiness of an adversary who
    may find a way to match your regex and still do something
    nasty.

    Examples:

      -
        allow:
          -
            # Touch the foo file, allowing any
            # optional command line params
            # before the filename

            command: ^touch\\s+(-\\S+\\s+)*foo$
            pcre_match: true
          -
            # attempt to allow rm of files in /var/tmp
            # but actually would fail to catch malicious
            # commands e.g. /var/tmp/../../etc/passwd
            #
            # As I said, be careful with pcre matching!!!

            command: ^/bin/rm\\s+(-\\S+\\s+)*/var/tmp/\\S*$
            pcre_match: true

## SCP SUBRULES

authprogs has special support for scp file transfer. You are not
required to use this - you could use a simple command subrules
to match explicit scp commands - but using an scp-specific
subrule offers you greater flexibility.

To trigger scp mode, use `rule_type: scp`.

The scp options are as follows.

* `rule_type: scp`: This indicates that this is an scp subrule.

* `allow_upload: true|false`:    Allow files to be uploaded to the ssh
server. Defaults to false.

* `allow_download: true|false`:  Allow files to be downloaded from the
ssh server. Defaults to false.

* `allow_recursion: true|false`:  Allow recursive (-r) file up/download.
Defaults to false.

* `allow_permissions: true|false`:  Allow scp to get/set the permissions
of the file/files being transfered.  Defaults to false.

* `files`:  The files option allows you to specify which file or files are
allowed to be tranfered. If this is not specified then transfers are
not restricted based on filename.

    Examples:

      -
        allow:
          - rule_type: scp
            allow_download: true
            files:
              - /etc/group
              - /etc/passwd
          - rule_type: scp
            allow_upload: true
            files: [/tmp/file1, /tmp/file2]


## EXAMPLES

Here is a sample configuration file with multiple rules,
going from simple to more complex.

Note that this config can be spread around between the
`~/.ssh/authprogs.yaml` and `~/.ssh/authprogs.d` directory.


    # All files should start with an initial solo dash -
    # remember, we're being concatenated with all other
    # files!

    # Simple commands, no IP restrictions.
    -
      allow:
        - command: /bin/tar czvf /backups/www.tgz /var/www/
        - command: /usr/bin/touch /var/www/.backups.complete

    # Similar, but with IP restrictions
    -
      from: [192.168.0.10, 192.168.0.15, 172.16.3.3]
      allow:
        - command: git --git-dir=/var/repos/foo/.git pull
        - command: sudo /etc/init.d/apache2 restart

    # Some more complicated subrules
    -
      # All of these 'allows' have the same 'from' restrictions
      from:
        - 10.1.1.20
        - 10.1.1.21
        - 10.1.1.22
        - 10.1.1.23
      allow:
        # Allow unrestricted ls
        - command: /bin/ls
          allow_trailing_args: true

        # Allow any 'service apache2 (start|stop)' commands via sudo
        - command: sudo service apache2
          allow_trailing_args:true

        # How about a regex? Allow wget of any https url, outputting
        #  to /tmp/latest
        - command: ^/usr/bin/wget\\s+https://\\S+\\s+-O\\s+/tmp/latest$
          pcre_match: true

        # Allow some specific file uploads
        - rule_type: scp
          allow_upload: true
          files:
            - /srv/backups/host1.tgz
            - /srv/backups/host2.tgz
            - /srv/backups/host3.tgz


## TROUBLESHOOTING

`--dump_config` is your friend. If your yaml config isn't parsing,
consider `--dump_config --logfile=/dev/tty` for more debug output
to find the error.


## FILES

* `~/.ssh/authorized_keys`: The default place your key should be installed
    and configured to call authprogs. The actual
    location can differ if your administrator
    has changed it.

* `~/.ssh/authprogs.yaml`: Default authprogs configuration file. Override with --configfile.

* `~/.ssh/authprogs.d`: Default authprogs configuration directory. Override with --configdir.

## ENVIRONMENT

authprogs uses the following environment variables that are set
by the sshd(8) binary:

* `SSH_CONNECTION`: This is used to determine the client IP address.

* `SSH_CLIENT`: This is used to determine the client IP address
    if SSH_CONNECTION was not present.

* `SSH_ORIGINAL_COMMAND`: The (squashed) original SSH command that was issued by the client.

authprogs sets the following environment variables for use by the
authenticated process

* `AUTHPROGS_KEYNAME`: the value of the --keyname command line. Will be set to an empty string if no --keyname was set.

## EXIT STATUS

authprogs returns 0 on success, non-zero on errors. In run mode it exits with
the exit code of the command that was requested, or 126 on unexpected errors.

## LOGGING AND DEBUGGING

If a `--logfile` is specified then it will be opened in append
mode and a line about each command that is attempted to be run
will be written to it. The line itself is in the form of a python
dictionary.

If authprogs is run with `--debug`, then this logfile will get increased
debugging information, including the configuration, rule matching status
as they are checked, etc.


## HISTORY

A perl version of authprogs was originally published
at http://www.hackinglinuxexposed.com/articles/20030115.html
in 2003. This is a complete rewrite in python, with a more
extensible configuration, and avoiding some of the limitations
of the former.

## SEE ALSO

ssh(1), sshd(8), scp(1).

## AUTHOR

Bri Hatch <bri@ifokr.org>
