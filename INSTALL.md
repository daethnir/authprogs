
INSTALLING
==========

Regardless if you have checked out the source tarball
or cloned the entire git repository, you should be able
to install authprogs in the standard setuptools-ian way:

        $ python3 setup.py test
        $ sudo python3 setup.py install


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

In order to generate the html man page from `doc/authprogs.md`
we require the markdown module which can be installed via

        $ sudo pip3 install markdown

or it may be available from your distro already, for example

        $ sudo apt install python3-markdown


There should be no other dependencies.
