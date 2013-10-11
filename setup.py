#!/usr/bin/env python
"""Authprogs setup.py"""

import authprogs
import multiprocessing
import os
import shutil
import subprocess

from setuptools import setup
from distutils.command.install import install
from distutils.command.sdist import sdist


def long_description():
    """Read our long description from the fs."""
    with open('doc/description.rst') as filed:
        return filed.read()


class APInstall(install):
    """Create man pages and share/doc files from markdown/etc source."""

    def run(self):
        top = os.path.join(os.path.dirname(__file__))
        doc = os.path.join(os.path.dirname(__file__), 'doc')
        man_md = os.path.join(doc, 'authprogs.md')
        man_ronn = os.path.join(doc, 'authprogs.1.ronn')
        man_1 = os.path.join(doc, 'authprogs.1')

        # Copy and convert the ronn-formatted man page
        shutil.copy(man_md, man_ronn)
        print 'running ronn'
        try:
            retval = subprocess.call(['ronn', '-r', man_ronn])
            print 'done ronn %s' % retval
            if retval != 0:
                raise Exception('ronn man page conversion failed, '
                                'returned %s' % retval)
        except:
            raise Exception('ronn required for manpage conversion - do you '
                            'have it installed?')

        # Let us handle installs from source and sdist
        readme = os.path.join(top, 'README')
        if os.path.exists(readme):
            install.run(self)
        else:
            shutil.copy(os.path.join(top, 'README.md'), readme)
            install.run(self)
            os.remove(readme)

        os.remove(man_ronn)
        os.remove(man_1)


class APSdist(sdist):
    """Copy README.md to README for sdist packaging."""

    def run(self):
        top = os.path.join(os.path.dirname(__file__))
        shutil.copy(os.path.join(top, 'README.md'),
                    os.path.join(top, 'README'))
        sdist.run(self)
        os.remove(os.path.join(top, 'README'))


setup(
    name='authprogs',
    version=authprogs.__version__,
    description='SSH Command Authenticator',
    long_description=long_description(),
    keywords='authprogs ssh pubkey identity authoried_keys security',
    url='http://github.com/daethnir/authprogs',
    author='Bri Hatch',
    author_email='bri@ifokr.org',
    license='GPLv2',
    maintainer='Bri Hatch',
    maintainer_email='bri@ifokr.org',
    scripts=['bin/authprogs'],
    packages=['authprogs'],
    data_files=[
        ('share/man/man1/', ['doc/authprogs.1']),
        ('share/doc/authprogs/', ['README', 'TODO.md', 'COPYING'])],
    test_suite='nose.collector',
    tests_require=['nose'],
    install_requires=['pyyaml'],
    zip_safe=False,
    cmdclass={"install": APInstall, "sdist": APSdist}
)
