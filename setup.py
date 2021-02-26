#!/usr/bin/env python3
import setuptools
import os
import pip
import pkg_resources


with open("README.md", "r") as fh:
    long_description = fh.read()


def parse_requirements_from_file(path):
    """Parses requirements from a requirements file.
    Args:
      path (str): path to the requirements file.
    Yields:
      pkg_resources.Requirement: package resource requirement.
    """
    with open(path, "r") as file_object:
        file_contents = file_object.read()
    for req in pkg_resources.parse_requirements(file_contents):
        try:
            requirement = str(req.req)
        except AttributeError:
            requirement = str(req)
        yield requirement


setuptools.setup(
    name="mans_to_es",
    version="1.7",
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
    install_requires=parse_requirements_from_file("requirements.txt"),
)
