#!/usr/bin/env python3
"""
Setup script for ASCSA-CI
For development installation: pip install -e .
For production installation: pip install .
"""

from setuptools import setup, find_packages

setup(
    packages=find_packages(exclude=['tests', 'tests.*', 'examples', 'examples.*']),
    include_package_data=True,
)
