
TODO List
===========

Below are things that I can envision implementing or improving.
The presense of something on this list does not mean that
it will be implemented.

Contributors are encouraged to reach out in advance
to kibbiz about implementation.

* security improvements
    * refuse to run if any files are world writeable

* logging improvements
    * Use standard python logging
    * add timestamps
    * change output of success
    * syslog support
    * add `--debug` to write traceback and more verbose errors

* key installation improvements
    * allow arbitrary `authorized_keys` ssh options, for
      example `no-pty`, `permitopen`, etc.
    * `--force` to overwrite key entries in `authorized_keys` when
      installing keys
    * command line option for authprogs path
    * identify installation attempt of private keys

* config rules improvements
    * chdir to a directory before running
    * set environment variables
    * set `$PATH`
    * restrictions additions
        * support for hostnames
        * time of day/week/etc
    * chroot to a different user via sudo before running
        * Would require your user has unrestricted sudo for this command

* command matching improvements
    * case-insensitive pcre
    * whitespace support (clunky/worrisome)
    * shell regex command matching

* forced command specification
    * allow you to match a command and then run something completely different

* ability to function as a login shell
    * would lose `--name` functionality

* rsync subrules
    * investigate --include / --exclude / --files-from
    * verify globbing support and security
    * support uploading to file that does not exist
      yet when using `files`. Currently it does a
      realpath check which fails since the file
      doesn't exist.
    * add option that allows access to any
      files under a given directory, rather than
      being explicit
    * create a cache for rsync\_realpaths to decrease
      lookups when files are listed in multiple rules
    * allow/disallow symlinks (-l)
    * support setting allowed rsync binary paths

* scp subrules
    * make scp handling check that the scp binary path is
      valid so to avoid any $PATH trickery, similar to how
      its done in rsync
    * support for `-v`
    * support for `-d` (targetshouldbedirectory)
