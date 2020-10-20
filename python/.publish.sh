#!/usr/bin/env bash

rm dist/*
pip3 install -U twine wheel setuptools
python3 setup.py sdist bdist_wheel
python3 -m twine upload dist/* --verbose

