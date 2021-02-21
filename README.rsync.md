
# Rsync option support

The overall plan is to fully parse the rsync command line.
Not all features, however, can be restricted by
`authprogs`, while others may have no security
ramifications.

Nonetheless the rsync command line **must** be considered
valid.

Support for more flags will be added as time allows, and
preference will be given to those flags that are reported
as actively needed.

Parsing was done based on the rsync-3.1.2 source code.

# How Rsync Works

rsync converts the client command line into server rsync
command via the server\_options function in options.c.
Only those options that the server needs to know are
actually passed onto the server.


# Limitations

Not all rsync options have been fully investigated, e.g.
the `--files-from` / `--filter` / `--include` / `--exclude`
ones. There ay be dragons.


# Weirdness

rsync overloads the -e flag. On the client it tells rsync
which program to use for 'ssh'. On the server it indicates
the protocol version to indicate the protocol. This option
is either `-e.` to indicate no version, or `-e#.#` when a
version has been negotiated.  When running over ssh, there
is no version, so this always starts as `-e`.

rsync then appends some pre-release protocol version and
behaviour flags information. These look like the single
letter options above but they are not. (For example the `C`
in `-e.C` means that the client supports a checksum seed
order fix, not that the `-C` (`--cvs-exclude`) flag is
being sent.

Authprogs currently recognises the -e option and ignores
its value.  For reference, as of rsync-3.1.2 this will
typically be `-e.LsfxC`)


# See also

For `authprogs`' rsync documentation and usage see authprogs.md.


