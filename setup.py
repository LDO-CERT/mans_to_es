#!/usr/bin/env python3
import setuptools
import os
import pip

pip_major_version = int(pip.__version__.split(".")[0])
pip_minor_version = int(pip.__version__.split(".")[1])
if pip_major_version >= 20:  # for pip >= 20
    from pip._internal.req import parse_requirements
    from pip._internal.network.session import PipSession
elif pip_major_version >= 10:
    from pip._internal.download import PipSession
    from pip._internal.req import parse_requirements
else:  # for pip <= 9.0.3
    from pip.download import PipSession
    from pip.req import parse_requirements


with open("README.md", "r") as fh:
    long_description = fh.read()

if (pip_major_version == 20 and pip_minor_version >= 1) or pip_major_version > 20:
    install_requires = [
        str(req.requirement)
        for req in parse_requirements("requirements.txt", session=PipSession(),)
    ]
else:
    try:
        install_requires = [
            str(req.req)
            for req in parse_requirements("requirements.txt", session=PipSession(),)
        ]
    except:
        install_requires = [
            str(req)
            for req in parse_requirements("requirements.txt", session=PipSession(),)
        ]

setuptools.setup(
    name="mans_to_es",
    version="1.6",
    author="LDO-CERT",
    author_email="gcert@leonardocompany.com",
    description="Send .mans to ElasticSearch",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache License, Version 2.0",
    url="https://github.com/LDO-CERT/mans_to_es",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    entry_points={"console_scripts": ["mans_to_es=mans_to_es.mans_to_es:main"]},
    install_requires=install_requires,
)
