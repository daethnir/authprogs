
INSTALLING
==========

Regardless if you have checked out the source tarball
or cloned the entire git repository, you should be able
to install authprogs in the standard setuptools-ian way:

        $ python setup.py test
        $ sudo python setup.py install


DEVELOPMENT
===========

Authprogs source can be found at its [github repository] 


BUILD REQUIREMENTS
------------------

In order to generate the man page from the `doc/authprogs.md`
file we require ronn, which can be found at [ronn]

Or it may be available in your distro already, for example

        $ sudo apt-get install ronn
   or
        $ sudo apt-get install ruby-ronn

There should be no other dependencies.


CONTRIBUTIONS
-------------

If you wish to make changes to authprogs, send a pull request.
Note that I plan to be very anal about unit testing; this is
security-related software after all.

Any code you provide will be assumed to be under the public
domain unless specified otherwise.

See the `TODO.md` file for ideas of things that need doing.


REPORTING BUGS
==============

Please file bug reports at the [github issues page]



[github issues page]: https://github.com/daethnir/authprogs/issues

[github repository]: https://github.com/daethnir/authprogs

[ronn]: https://github.com/rtomayko/ronn
