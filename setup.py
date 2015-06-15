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


# Documents that should be converted or renamed from markdown
MARKDOWN2HTML = ['authprogs']
MARKDOWN2TEXT = ['AUTHORS', 'INSTALL', 'README', 'TODO']

if sys.version_info[0] == 2:
    console_script = 'authprogs'
else:
    console_script = 'authprogs%d' % sys.version_info.major

def long_description():
    """Read our long description from the fs."""
    with open('doc/description.rst') as filed:
        return filed.read()


def runcmd(command, command_input=None, cwd=None):
    """Run a command, potentially sending stdin, and capturing stdout/err."""
    proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=cwd)
    (stdout, stderr) = proc.communicate(command_input)
    if proc.returncode != 0:
        sys.stderr.write('ABORTING: command "%s" failed w/ code %s:\n'
                         '%s\n%s' % (command, proc.returncode,
                                     stdout, stderr))
        sys.exit(proc.returncode)
    return proc.returncode, stdout, stderr


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
            if not os.path.exists(man_1):
                shutil.copy(man_md, man_ronn)
                self.created.append(man_ronn)
                retval = subprocess.call(['ronn', '-r', man_ronn])
                if retval != 0:
                    raise Exception('ronn man page conversion failed, '
                                    'returned %s' % retval)
                self.created.append(man_1)
        except:
            raise Exception('ronn required for manpage conversion - do you '
                            'have it installed?')

        # Markdown files in docs dir get converted to .html
        for name in MARKDOWN2HTML:
            htmlfile = os.path.join(doc, '%s.html' % name)
            if os.path.exists(htmlfile):
                continue

            target = open(htmlfile, 'w')
            self.created.append(htmlfile)
            stdout = runcmd(['python', '-m', 'markdown',
                             os.path.join(doc, '%s.md' % name)])[1]
            if not stdout:
                raise Exception('markdown conversion failed, no output.')
            target.write(stdout)
            target.close()

        # Markdown files in top level just get renamed sans .md
        for name in MARKDOWN2TEXT:
            target = os.path.join(top, name)
            if os.path.exists(target):
                continue
            source = os.path.join(top, '%s.md' % target)
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
    keywords='authprogs ssh pubkey identity authoried_keys security',
    url='http://github.com/daethnir/authprogs',
    author='Bri Hatch',
    author_email='bri@ifokr.org',
    license='GPLv2',
    maintainer='Bri Hatch',
    maintainer_email='bri@ifokr.org',
    packages=['authprogs'],
    data_files=[
        ('share/man/man1/', ['doc/authprogs.1']),
        ('share/doc/authprogs/',
         ['AUTHORS', 'COPYING', 'INSTALL', 'README',
          'TODO', 'doc/authprogs.html'])],
    test_suite='authprogs.tests',
    setup_requires=['markdown'],
    install_requires=['pyyaml'],
    zip_safe=False,
    cmdclass={"install": APInstall, "sdist": APSdist},
    entry_points={
        'console_scripts': ['%s = authprogs.authprogs:main' % console_script]
    },
)
