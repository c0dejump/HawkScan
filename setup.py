# Author:
# Nathan Faillenot (codejump - @c0dejump)

import pathlib
import setuptools
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="HawkScan",
    version="2.1",
    author="c0dejump",
    author_email="codejumpgame@gmail.com",
    description="Security Tool for Reconnaissance and Information Gathering on a website. (python 3.x)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["static"]),
    include_package_data=True,
    url="https://github.com/c0dejump/HawkScan/",
    install_requires=[
        'requests',
        'pyopenssl',
        'queuelib',
        'fake_useragent',
        'argparse',
        'bs4',
        'dnspython',
        'wafw00f',
        'python-whois',
        'sockets',
        'python-engineio==3.14.2',
        'python-socketio[client]==4.6.0',
        'google',
        'notifypy'
    ],
    project_urls={
        "Bug Tracker": "https://github.com/c0dejump/HawkScan/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)