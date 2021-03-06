# Author:
# Nathan Faillenot (codejump - @c0dejump)

import pathlib
import setuptools
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="HawkScan",
    version="1.7.3",
    author="c0dejump",
    author_email="codejumpgame@gmail.com",
    description="Security Tool for Reconnaissance and Information Gathering on a website. (python 2.x & 3.x)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["static"]),
    include_package_data=True,
    url="https://github.com/c0dejump/HawkScan/",
    install_requires=[
        'requests',
        'pyopenssl',
        'prettyprinter',
        'prettyprint',
        'queuelib',
        'fake_useragent',
        'python-whois',
        'argparse',
        'bs4',
        'dnspython',
        'wafw00f',
        'python-whois',
        'sockets',
        'urlparser'
    ],
    project_urls={
        "Bug Tracker": "https://github.com/c0dejump/HawkScan/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
