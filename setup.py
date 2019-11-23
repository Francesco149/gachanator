#!/bin/env python3

from setuptools import setup, find_packages

gachanator_classifiers = [
    "Programming Language :: Python :: 3",
    "Intended Audience :: Developers",
    "License :: Public Domain",
    "Topic :: Software Development :: Libraries",
    "Topic :: Utilities"
]

with open("README.rst", "r") as f:
  gachanator_readme = f.read()

setup(
    name="gachanator",
    version="0.1.0",
    author="Franc[e]sco",
    author_email="lolisamurai@tfwno.gf",
    url="https://github.com/Francesco149/gachanator",
    packages=find_packages("."),
    description="extensible gacha game headless client/swiss-knife lib",
    long_description=gachanator_readme,
    license="Unlicense",
    classifiers=gachanator_classifiers,
    keywords="gacha headless client bot",
    install_requires=[
        "oscrypto", "appdirs", "pyasn1", "push_receiver", "tendo"
    ]
)
