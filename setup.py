#!/usr/bin/env python
"""Authprogs setup.py"""

# pylint: disable-msg=W0511
# pylint: disable-msg=R0904

import authprogs
import os
import shutil
import subprocess
import sys

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.sdist import sdist


# Allowed version list
if sys.version_info < (3, 3):
    sys.exit('Sorry, Python < 3.3 is not supported')


# Documents that should be converted or renamed from markdown
MARKDOWN2HTML = ['authprogs']
MARKDOWN2TEXT = [
    'AUTHORS',
    'DEVELOPMENT',
    'INSTALL',
    'README',
    'README.rsync',
    'TODO',
]

console_script = 'authprogs'


def needsupdate(target, source):
    uptodate = (
        os.path.exists(target)
        and os.stat(target).st_mtime >= os.stat(source).st_mtime
    )
    return not uptodate


def long_description():
    """Read our long description from the fs."""
    with open('doc/description.rst') as filed:
        return filed.read()


class Converter(object):
    """Documentation conversion class."""

    def __init__(self):
        """Init."""
        self.created = []

    def dd_docs(self):
        """Copy and convert various documentation files."""
        top = os.path.join(os.path.dirname(__file__))
        doc = os.path.join(top, 'doc')

        # Markdown to ronn to man page
        man_md = os.path.join(doc, 'authprogs.md')
        man_ronn = os.path.join(doc, 'authprogs.1.ronn')
        man_1 = os.path.join(doc, 'authprogs.1')

        # Create manpage
        try:
            if needsupdate(man_1, man_md):
                shutil.copy(man_md, man_ronn)
                self.created.append(man_ronn)
                retval = subprocess.call(['ronn', '-r', man_ronn])
                if retval != 0:
                    raise Exception(
                        'ronn man page conversion failed, '
                        'returned {}'.format(retval)
                    )
                self.created.append(man_1)
        except:
            raise Exception(
                'ronn required for manpage conversion - do you '
                'have it installed?'
            )

        # Markdown files in docs dir get converted to .html
        for name in MARKDOWN2HTML:
            htmlfile = os.path.join(doc, '{}.html'.format(name))
            source = os.path.join(doc, '{}.md'.format(name))
            if not needsupdate(htmlfile, source):
                continue

            target = open(htmlfile, 'w')
            self.created.append(htmlfile)
            command = ['python3', '-m', 'markdown', source]
            proc = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if proc.returncode != 0:
                raise Exception(
                    'Markdown conversion failed,'
                    ' no output. {}'.format(proc.stderr.decode())
                )
            target.write(proc.stdout.decode())
            target.close()

        # Markdown files in top level just get renamed sans .md
        for name in MARKDOWN2TEXT:
            target = os.path.join(top, name)
            source = os.path.join(top, '{}.md'.format(target))
            if not needsupdate(target, source):
                continue
            shutil.copy(source, target)
            self.created.append(target)

    def rm_docs(self):
        """Remove converted docs."""
        for filename in self.created:
            if os.path.exists(filename):
                os.unlink(filename)


class APInstall(install):
    """Create man pages and share/doc files from markdown/etc source."""

    def run(self):
        converter = Converter()

        converter.dd_docs()
        install.run(self)
        converter.rm_docs()


class APSdist(sdist):
    """Convert markdown for sdist packaging."""

    def run(self):
        converter = Converter()

        converter.dd_docs()
        sdist.run(self)
        converter.rm_docs()


setup(
    name='authprogs',
    version=authprogs.__version__,
    description='SSH Command Authenticator',
    long_description=long_description(),
    keywords='authprogs ssh pubkey identity authorized_keys security',
    url='http://github.com/daethnir/authprogs',
    author='Bri Hatch',
    author_email='bri@ifokr.org',
    license='GPLv2',
    maintainer='Bri Hatch',
    maintainer_email='bri@ifokr.org',
    packages=['authprogs'],
    data_files=[
        ('share/man/man1/', ['doc/authprogs.1']),
        (
            'share/doc/authprogs/',
            [
                'AUTHORS',
                'DEVELOPMENT',
                'COPYING',
                'INSTALL',
                'README',
                'TODO',
                'doc/authprogs.html',
            ],
        ),
    ],
    test_suite='authprogs.tests',
    setup_requires=['markdown'],
    install_requires=['pyyaml'],
    zip_safe=False,
    cmdclass={"install": APInstall, "sdist": APSdist},
    entry_points={
        'console_scripts': [
            '{} = authprogs.authprogs:main'.format(console_script)
        ]
    },
)
