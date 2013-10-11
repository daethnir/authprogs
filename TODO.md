
TODO List
===========

Below are things that I can envision implementing or improving.
The presense of something on this list does not mean that
it will be implemented.

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
        * client IP matching changes
        * support for hostnames
        * CIDR/netmask processing
        * time of day/week/etc
    * chroot to a different user via sudo before running
        * Would require your user has unrestricted sudo for this command

* command matching improvements
    * case-insensitive pcre
    * whitespace support (clunky/worrisome)
    * shell regex command matching
    * scp parsing additions
        * support for `-v`
        * support for `-d` (targetshouldbedirectory)
    * new smart command support
        * rsync support

* forced command specification
    * allow you to match a command and then run something else

* ability to function as a login shell
    * would lose `--name` functionality
