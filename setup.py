#!/usr/bin/env python3
import setuptools
import os

try:  # for pip >= 10
    from pip._internal.download import PipSession
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.download import PipSession
    from pip.req import parse_requirements

    
with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mans_to_es",
    version="1.0",
    author="LDO-CERT",
    author_email="gcert@leonardocompany.com",
    description="Send .mans to ElasticSearch",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='Apache License, Version 2.0',
    url="https://github.com/LDO-CERT/mans_to_es",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    entry_points={'console_scripts': ['mans_to_es=mans_to_es.mans_to_es:Main']},
    install_requires=[str(req.req) for req in parse_requirements(
        'requirements.txt', session=PipSession(),
    )],
)