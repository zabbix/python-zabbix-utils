# zabbix_utils
#
# Copyright (C) 2001-2023 Zabbix SIA
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import re
import setuptools
from zabbix_utils.version import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    regexp = r'(?<=##)\s*Get started\n*(^\*.*\n){1,10}\n*##'
    long_description = re.sub(regexp, '', fh.read(), flags=re.M)

setuptools.setup(
    name="zabbix_utils",
    version=__version__,
    author="Zabbix SIA",
    author_email="integrationteam@zabbix.com",
    maintainer="Aleksandr Iantsen",
    maintainer_email="aleksandr.iantsen@zabbix.com",
    description="A library with modules for working with Zabbix (Zabbix API, Zabbix sender, Zabbix get)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="monitoring zabbix api sender get utils tools",
    url="https://github.com/zabbix/python-zabbix-utils",
    test_suite='tests',
    packages=["zabbix_utils"],
    tests_require=["unittest"],
    install_requires=[],
    extras_require={
        "async": ["aiohttp>=3,<4"],
    },
    python_requires='>=3.8',
    project_urls={
        'Zabbix': 'https://www.zabbix.com/documentation/current',
        'Source': 'https://github.com/zabbix/python-zabbix-utils',
        'Changes': 'https://github.com/zabbix/python-zabbix-utils/blob/main/CHANGELOG.md',
        'Bug Tracker': 'https://github.com/zabbix/python-zabbix-utils/issues'
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology"
	]
)
