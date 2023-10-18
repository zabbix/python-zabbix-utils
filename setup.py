import setuptools
from zabbix_utils.version import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

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
    install_requires=["typing_extensions>=4.0.0;python_version<'3.11'"],
    python_requires='>=3.7',
    project_urls={
        'Zabbix': 'https://www.zabbix.com/documentation/current',
        'Source': 'https://github.com/zabbix/python-zabbix-utils',
        'Changes': 'https://github.com/zabbix/python-zabbix-utils/blob/main/CHANGELOG.md',
        'Bug Tracker': 'https://github.com/zabbix/python-zabbix-utils/issues'
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
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
