
Authprogs
---------

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

For usage see the full authprogs man page in the doc directory.

