#!/usr/bin/env bash

echo "Test aes256 python2"
python2 -m unittest2 src/tests/test_aes256.py

echo "Test aes256 python3"
python3 -m unittest  src/tests/test_aes256.py
