
Authprogs Development
=====================

Reporting Bugs
--------------

Please file bug reports at the [github issues page] or reach
out to the author directly.

Contributions
-------------

If you wish to make changes to authprogs, send a pull request.
Note that I plan to be very anal about unit testing; this is
security-related software after all.

Any code you provide will be assumed to be under the public
domain unless specified otherwise.

Contributors are encouraged to reach out in advance
to kibbiz about implementation.

See the `TODO.md` file for ideas of things that need doing.

Testing
-------

Run local unit tests:

    $ python3 setup.py test

When developing, it may be useful to run individual unit or per-file tests, e.g.

    $ python3 setup.py test -s authprogs.tests.test_rsync.RsyncTests.test_foo
    $ python3 setup.py test -s authprogs.tests.test_authprogs.AuthprogsTests.test_archive

And install locally to do live tests

    $ sudo python3 setup.py install

Spell check
-----------

Enough spelingerrers have cropped up that it's worth having a defined
pass for spell check. The repo includes `ispell` dictionaries which have
been populated with words specifically for the prose, code, and yaml files.

    # Docs
    ispell -p .ispell_default $(git ls-tree -r $(git branch --show-current) --name-only | egrep -i '\.md$|\.rst$')

    # Code files
    ispell -p .ispell_code $(git ls-tree -r $(git branch --show-current) --name-only | egrep -i '\.py$')

    # yaml
    ispell -p .ispell_yaml $(git ls-tree -r $(git branch --show-current) --name-only | egrep -i '\.yaml$')

Publishing
----------

Upload to test pypi:

    $ python3 setup.py sdist upload -r testpypi
    $ sudo pip3 install -U -i https://test.pypi.org/simple/ authprogs
    $ sudo pip3 install -U -i https://test.pypi.org/simple/ authprogs==X.Y.Z


Test locally to verify all's good.

Upload to prod pypi:

    $ python3 setup.py sdist upload
    $ sudo pip3 uninstall authprogs
    $ sudo pip3 install authprogs



[github issues page]: https://github.com/daethnir/authprogs/issues

[github repository]: https://github.com/daethnir/authprogs

[ronn]: https://github.com/rtomayko/ronn
