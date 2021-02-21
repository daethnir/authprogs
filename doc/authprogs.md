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

Passwordless SSH using ssh identities or pubkeys can enable all
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

You can install your ssh identities/pubkeys manually, or allow `authprogs` to do the work for you.

## MANUAL KEY INSTALLATION

You need to set up your `~/.ssh/authorized_keys` file to force
invocation of `authprogs` for the key or keys you wish to protect.

A line of an unrestricted `authorized_key` entry might look like this:

    ssh-rsa AAAAxxxxx...xxxxx user@example.com

When setting up this key to use `authprogs`, you add a `command=` option
to the very beginning of that line that points to the location where
authprogs lives. For example if `authprogs` is in `/usr/bin/authprogs`,
you would use this:

    command="/usr/bin/authprogs --run" ssh-rsa AAAAxxxxx...xxxxx user@example.com

You must include `--run` to let `authprogs` know it is running in SSH command mode.

Authprogs has other command line options you may wish to include
as well, for example

    command="/usr/bin/authprogs --keyname=backups --run" ssh-rsa AAAA...xxxxx user@example.com

Lastly, if you wish, ssh offers a number of other helpful
restrictions you may wish to include that are separate from
authprogs. These can be appended right after (or before) the
command="" section if you wish.

    command="/usr/bin/authprogs --run",no-port-forwarding,no-pty ssh-rsa AAAA...xxxxx user@example.com

See the sshd(8) man page for more information about allowed
`authorized_keys` configuration options.

## AUTOMATED KEY INSTALLATION

Authprogs is capable of adding your key to your `authorized_keys`
file (`~/.ssh/authorized_keys` by default) programmatically. It
also disables ssh port forwarding by default for this key (a
sensible default for most batch jobs.)

authprogs will refuse to install a key that is already present
in the `authorized_keys` file.

For example the following

    authprogs --install_key /path/to/backups_key.pub --keyname=backups

would cause the following line to be added to your
`~/.ssh/authorized_keys` file:

    command="/usr/bin/authprogs --keyname backups --run",no-port-forwarding ssh-rsa AAAA...xxxxx user@example.com

## RUN MODE OPTIONS

Authprogs can run in several modes, depending on which of these
command line switches you provide.

* `--run`:
   Act in run mode, as from an `authorized_keys` file.

* `--install_key filename`:
  Install the key contained in the named file into your `authorized_keys` file.

* `--dump_config`:
  Dump the configuration in a python-style view. Helpful only for debugging.

* `--silent`:
  Do not inform the user if their command has been rejected. Default is
  to let them know it was rejected to prevent confusion.

* `--help`:
  Show help information

## OTHER OPTIONS

The following options may apply to multiple run modes, as appropriate.

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
    Specifies the `authprogs` configuration file to read.
    Defaults to `~/.ssh/authprogs.yaml`.

    In key installation mode, this adds the `--configfile`
    option to the `authorized_keys` entry.

* `--configdir`:
     Specifies the `authprogs` configuration, in which
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
what spaces in `SSH_ORIGINAL_COMMAND` were between arguments and which
were part of arguments.

Here are some commands that would not work through `authprogs`:

* `ssh host "rm /tmp/foo; touch /tmp/success"`
* `ssh host "rm /tmp/*.html"`
* `ssh host "cut -d: -f 1 /etc/passwd > /tmp/users"`
* `ssh host "touch '/tmp/file with spaces'"`
* `ssh host "for file in /tmp/*.html; do w3m -dump $file > $file.txt; done"`

You can work around these limitations by writing a shell script that
does what you need and calling that from `authprogs`, rather than attempting
to run complicated command lines via ssh directly.

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

All the `authprogs` configuration files are concatenated
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

Note that the command must be *exactly* the same; `authprogs` is not
aware of arguments supported by a command, so it cannot realise that
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

## RSYNC SUBRULES

authprogs has special support for rsync file transfer. You are not
required to use this - you could use a simple command subrules
to match explicit rsync commands - but using an rsync-specific
subrule offers you greater flexibility.

Rsync support is in beta, so please raise any bugs found. Supporting
the full set of rsync command line options is a moving target.

To specify rsync mode, use `rule_type: rsync`.

The rsync options are as follows.

* `rule_type: rsync`: This indicates that this is an rsync subrule.

* `allow_upload: false|true`: Allow files to be uploaded to the ssh
server. Defaults to false.

* `allow_download: false|true`:  Allow files to be downloaded from the
ssh server. Defaults to false.

* `allow_archive: false|true`:  Allow file archive, i.e. the options
  that are set when using `-a` or `--archive`. This is used to simplify
  `authprogs` configuration files. Specifying this and negating one of
  he associated options (e.g. `allow_recursive: false`) is considered
  an error.  Defaults to false.

* `paths`: a list of explicit files/directories that are allowed to match. Files
  specified by the client will be resolved via `realpath` to avoid any
  symlink trickery, so members of `paths` must be the real paths.

  WARNING: specifying a directory in `paths` would allow rsync to
  act on any files therein at potentially infinite depth, e.g. when
  `allow_recursive` is set, or the client uses `--files-from`. If you
  want to restrict to specific files you must name them explicitly.

  See RSYNC SYMLINK SUPPORT for potential limitations to `paths`.

* `path_startswith`: a list of pathname prefixes that are allowed to match.
  Files specified by the client will be resolved via `realpath` and if they
  start with the name provided then they will be allowed.

  This is a simple prefix match. For example if you had

        path_startswith: [ /tmp ]

  then it would match all of the following

        /tmp
        /tmp/
        /tmpfiles      # may not be what you meant!
        /tmp/foo.txt
        /tmp/dir1/dir2/bar.txt

  If you want it to match only a directory (and any infinite subdirectories)
  be sure to include a trailing slash, e.g. `/tmp/`

  See RSYNC SYMLINK SUPPORT for potential limitations to `paths`.

* `allow_acls: false|true`:  Allow syncing of file ACLs. (`--acls`). Defaults to false.

* `allow_checksum: true|false`:  Allow checksum method for identifying files that need syncing. (`-c` / `--checksum`)  Defaults to true.

* `allow_debug: true|false`: Allow fine-grained debug verbosity. (`--debug FLAGS`). No support for sanity
checking the debug flags that are specified. Defaults to true.

* `allow_delete: false|true`:  Allow any of the delete options. (`--del` `--delete` `--delete-after` `--delete-before` `--delete-delay` `--delete-during` `--delete-excluded` `--delete-missing-args`). Defaults to false.


* `allow_devices: false|true`:  Allow syncing of device files. (`--devices`). Defaults to false.

* `allow_group: false|true`:  Allow group change. (`-g --group`). Defaults to false.

* `allow_info: true|false`: Allow fine-grained info verbosity. (`-info FLAGS`). No support for sanity
checking the info flags that are specified. Defaults to true.

* `allow_links: false|true`:  Allow copying symlinks as symlinks. (`-l --links`). Defaults to false.

* `allow_group: false|true`:  Allow ownership change. (`-o --owner`). Defaults to false.

* `allow_perms: false|true`:  Allow perms change. (`-p --perms`). Defaults to false.

* `allow_recursive: false|true`:  Allow recursive sync. (`-r --recursive`). Defaults to false.

* `allow_specials: false|true`:  Allow syncing of special files, e.g. fifos. (`--specials`). Defaults to false.

* `allow_times: true|false`:  Allow setting synced file times. (`-t --times`). Defaults to true.

* `allow_verbose: true|false|#`:  Allow verbose output. (`-v --verbose`). Rsync allows multiple
-v options, so this option accepts true (allow any verbosity), false (deny any verbosity), or a number
which indicates the maximum number of `-v` option that are allowed, e.g. `2` would allow `-v` or `-vv` but
not `-vvv`.  Defaults to true.




### RSYNC COMMAND LINE OPTIONS

Not all rsync options are currently implemented in `authprogs`.

If an option is listed as "<not implemented>" then there are two possibilities
in how `authprogs` will behave:

    * if the option is no actually sent on the remote command line then
      `authprogs` is blissfully unaware and the command will succeed.
      Many options are actually client-side only. We have not thoroughly
      investigated every single option yet.

    * if the option is sent on the remote command line then `authprogs`
      will fail.

Here is the list of rsync options and their current `authprogs` support status:


    rsync client arg             authprogs support
    ----------------             -----------------

        --append                   <not implemented>
        --append-verify            <not implemented>
        --backup-dir               <not implemented>
        --bwlimit                  <not implemented>
        --checksum-seed            <not implemented>
        --chown                  converted to --usermap and --groupmap
        --compare-dest             <not implemented>
        --compress-level           <not implemented>
        --contimeout               <not implemented>
        --copy-dest                <not implemented>
        --copy-unsafe-links        <not implemented>
        --debug                  allow_debug
        --del                    allow_delete
        --delay-updates            <not implemented>
        --delete                 allow_delete
        --delete-after           allow_delete
        --delete-before          allow_delete
        --delete-delay           allow_delete
        --delete-during          allow_delete
        --delete-excluded        allow_delete
        --delete-missing-args    allow_delete
        --devices                allow_devices
        --existing                 <not implemented>
        --fake-super               <not implemented>
        --files-from               <not implemented>
        --force                    <not implemented>
        --groupmap                 <not implemented>
        --iconv                    <not implemented>
        --ignore-errors            <not implemented>
        --ignore-existing          <not implemented>
        --ignore-missing-args      <not implemented>
        --info                   allow_info
        --inplace                  <not implemented>
        --link-dest                <not implemented>
        --list-only                <not implemented>
        --log-file                 <not implemented>
        --log-file-format          <not implemented>
        --max-delete               <not implemented>
        --max-size                 <not implemented>
        --min-size                 <not implemented>
        --new-compress             <not implemented>
        --no-XXXXX                 <not implemented> (negating options, e.g. --no-r)
        --numeric-ids              <not implemented>
        --only-write-batch         <not implemented>
        --outbuf                   <not implemented>
        --partial                  <not implemented>
        --partial-dir              <not implemented>
        --preallocate              <not implemented>
        --protocol                 <not implemented>
        --read-batch               <not implemented>
        --remove-sent-files        <not implemented> # deprecated version of remove-source-files
        --remove-source-files      <not implemented>
        --safe-links               <not implemented>
        --size-only                <not implemented>
        --skip-compress            <not implemented>
        --specials               allow_specials
        --stats                    <not implemented>
        --stop-at                  <not implemented>
        --suffix                   <not implemented>
        --super                    <not implemented>
        --time-limit               <not implemented>
        --timeout                  <not implemented>
        --usermap                  <not implemented>
        --write-batch              <not implemented>
    -0, --from0                    <not implemented>
    -@, --modify-window            <not implemented>
    -A, --acls                   allow_acls
    -B, --block-size               <not implemented>
    -C, --cvs-exclude              <not implemented>
    -D                           allow_devices and allow_specials
    -E, --executability            <not implemented>
    -H, --hard-links               <not implemented>
    -I, --ignore-times             <not implemented>
    -J, --omit-link-times          <not implemented>
    -K, --keep-dirlinks            <not implemented>
    -L, --copy-links               <not implemented>
    -O, --omit-dir-times           <not implemented>
    -P                           Same as --partial --progress
    -R, --relative                 <not implemented>
    -S, --sparse                   <not implemented>
    -T, --temp-dir                 <not implemented>
    -W, --whole-file               <not implemented>
    -X, --xattrs                   <not implemented>
    -a, --archive                Same as -rlptgoD; See those options
        --progress                 <not implemented>
    -b, --backup                   <not implemented>
    -c, --checksum               allow_checksum
    -d, --dirs                     <not implemented>
    -f, --filter                   <not implemented>
    -g, --group                  allow_group
    -i, --itemize-changes          <not implemented>
    -k, --copy-dirlinks            <not implemented>
    -l, --links                  allow_links
    -m, --prune-empty-dirs         <not implemented>
    -n, --dry-run                  <not implemented>
    -o, --owner                  allow_owner
    -p, --perms                  allow_perms
    -r, --recursive              allow_recursive
    -s, --protect-args             <not implemented>
    -t, --times                  allow_times
    -u, --update                   <not implemented>
    -v, --verbose                allow_verbose
    -x, --one-file-system          <not implemented>
    -y, --fuzzy                    <not implemented>
    -z, --compress                 <not implemented>
        --checksum-choice=STR      <not implemented>
        --exclude-from             <not implemented>
        --exclude                  <not implemented>
        --include-from             <not implemented>
        --include                  <not implemented>
        --rsync-path               <not implemented>
        --out-format               <not implemented>

The following are server-side only options that are supported

    -e, --rsh=COMMAND            Value ignored (indicates protocol feature support)
    --sender                     When present means download from server,
                                 when absent means upload to server.
    --server                     Always present on server


The following rsync client options are only relevant to daemon mode (i.e.
rsync daemon listening on TCP directly without SSH) or do not end up
on the server command line and are thus re not taken into consideration
when determining if the command is or is not allowed:

        --address               Client-only option
        --chmod                 Client-only option
                                   (Permissions are indicated via rsync
                                    protocol, not command line flags.)
        --blocking-io           Client-only option
        --daemon                Daemon-only option
        --msgs2stderr           Client-only option
        --munge-links           Client-only option
        --no-motd               Client-only option
        --noatime               Client-only option
        --password-file         Daemon-only option
        --port                  Client-only option
        --sockopts              Daemon-only option
        --version               Client-only option
    -4, --ipv4                  Client-only option
    -6, --ipv6                  Client-only option
    -8, --8-bit-output          Client-only option
    -F                          Client-only option (see --filter)
    -M, --remote-option=OPTION  Client-only option
    -h, --human-readable        Client-only option
    -q, --quiet                 Client-only option


### RSYNC BINARY PATH

Rsync must be at an official path to prevent a user's environment from
choosing one of their programs over the official one. Official paths are

    * /usr/bin/rsync
    * /usr/local/bin/rsync

A user who specifies --rsync-path with a different value, or who has
an rsync program earlier in their $PATH will be denied.

### RSYNC SYMLINK SUPPORT

Rsync has multiple ways of handling symlinks depending on command line
parameters and what component(s) of a path are symlinks.

If you are using `paths` or `paths_startswith` to limit what files
may be uploaded/downloaded then its your responsibility to assure
that symlink games are not used to exceed the desired restrictions.

For example if the file `/tmp/me.txt` is a symlink to `/home/wbagg/me.txt`
and you had

    - rule\_type: rsync
        allow_upload: true
        paths:
            - /tmp/me.txt

then if the user ran

    rsync /some/local/file remote:/tmp/me.txt

then rather than updating the file at `/home/wbagg.me.txt`, the
symlink at `/tmp/me.txt` would be replaced with a normal file.

A future update to `authprogs` may attempt to handle symlinks by
calling `os.path.realpath` prior to doing comparisons.


### RSYNC PATHNAME GOTCHA

Say you wanted to restrict uploads to just the file `/tmp/foo.txt`, you'd
use the following rsync subrule::

    - rule\_type: rsync
      allow_upload: true
      paths:
        - /tmp/foo.txt

From an end-user perspective both of these commands would seem to be
allowed from the client machine because they'd create a file on
the remote named `/tmp/foo.txt`:

    $ rsync foo.txt remote:/tmp/foo.txt  # provide full target filename
    $ rsync foo.txt remote:/tmp          # imply source name for target

However you'll find that only the first one works! This is because
`authprogs` on the server side sees literally just `/tmp` in the second
case.

Thus if you wanted to restrict uploads to just the file `/tmp/foo.txt`
then on the client side you **must** run the first (explicit
filename) rsync command.

### RSYNC SUBRULE KNOWN AND POSSIBLE BUGS

* If uploading to a file that does not yet exist when you've
  set `paths` this will fail. Adding a new `allow_create` option
  is the most likely solution here, but not yet implemented.

* No investigation of the rsync options --include / --exclude / --files-from
  has yet been performed - may affect path matching security.

* Though we do expand file globs and check each individual path
  that is returned, we do not explicitly use these resolved
  files when calling rsync. (Reason: it's possible we exceed the
  allowed size of a command line with globs that return many files.)
  As such if rsync's glob and `shutils.glob` have different behaviour
  we may have false positives or negatives.

* When `allow_download` is disabled client should not be able to get file
  contents. However since rsync transfers checksums as part of its protocol
  it is possible that information about server file contents could be gleaned
  by comparing checksums to possible content checksums when doing uploads.

## SCP SUBRULES

authprogs has special support for scp file transfer. You are not
required to use this - you could use a simple command subrules
to match explicit scp commands - but using an scp-specific
subrule offers you greater flexibility.

To specify scp mode, use `rule_type: scp`.

The scp options are as follows.

* `rule_type: scp`: This indicates that this is an scp subrule.

* `allow_upload: false|true`:    Allow files to be uploaded to the ssh
  server. Defaults to false.

* `allow_download: false|true`:  Allow files to be downloaded from the
  ssh server. Defaults to false.

* `allow_recursive: false|true`:  Allow recursive (-r) file up/download.
  Defaults to false.

* `allow_recursion: false|true`:  Deprecated version of `allow_recursive`.
  will be removed in 1.0 release.

* `allow_permissions: true|false`:  Allow scp to get/set the permissions
  of the file/files being transferred.  Defaults to false.

* `paths`:  The paths option allows you to specify which file or files are
  allowed to be transferred. If this is not specified then transfers are
  not restricted based on filename.

    Examples:

      -
        allow:
          - rule_type: scp
            allow_download: true
            paths:
              - /etc/group
              - /etc/passwd
          - rule_type: scp
            allow_upload: true
            paths: [/tmp/file1, /tmp/file2]


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
          paths:
            - /srv/backups/host1.tgz
            - /srv/backups/host2.tgz
            - /srv/backups/host3.tgz

        # Allow rsync to upload everything, deny any download
        - rule_type: rsync
          allow_upload: true

        # Allow rsync to recursively sync /tmp/foo/ to the server
        # in archive mode (-a, or any subset of -logptrD)
        # but do not allow download
        - rule_type: rsync
          allow_upload: true
          allow_recursive: true
          allow_archive: true
          paths:
            - /tmp/foo

        # Allow rsync to write some specific files and any individual
        #   files under /data/lhc/ directory, such as /data/lhc/foo
        #   or /data/lhc/subdir/foo.
        #
        # Disallow download (explicitly listed) or recursive
        #    upload (default false).
        - rule_type: rsync
          allow_upload: true
          allow_download: false
          paths:
            - /srv/htdocs/index.html
            - /srv/htdocs/status.html
          path_startswith:
            - /data/lhc/


## TROUBLESHOOTING

`--dump_config` is your friend. If your yaml config isn't parsing,
consider `--dump_config --logfile=/dev/tty` for more debug output
to find the error.


## FILES

* `~/.ssh/authorized_keys`: The default place your key should be installed
    and configured to call `authprogs`. The actual
    location can differ if your administrator
    has changed it.

* `~/.ssh/authprogs.yaml`: Default `authprogs` configuration file. Override with --configfile.

* `~/.ssh/authprogs.d`: Default `authprogs` configuration directory. Override with --configdir.

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

On unexpected error or rejecting the command `authprogs` will exit 126.

If the command was accepted then it returns the exit code of the command
that was run.

Note that if you're invoking ssh via another tool that program
may provide a different exit status and provide a misleading
error message when `authprogs` returns a failure, For example
`rsync` will exit 12 and assume a "protocol problem" rather
than a rejection on the server side.

## LOGGING AND DEBUGGING

If a `--logfile` is specified then it will be opened in append
mode and a line about each command that is attempted to be run
will be written to it. The line itself is in the form of a python
dictionary.

If `authprogs` is run with `--debug`, then this logfile will get increased
debugging information, including the configuration, rule matching status
as they are checked, etc.


## HISTORY

A perl version of `authprogs` was originally published
at https://www.hackinglinuxexposed.com/articles/20030115.html
in 2003. This is a complete rewrite in python, with a more
extensible configuration, and avoiding some of the limitations
of the former.

## SEE ALSO

ssh(1), sshd(8), scp(1).

## AUTHOR

Bri Hatch <bri@ifokr.org>
