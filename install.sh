#!/bin/bash

# Install the required packages
pip install -r requirements.txt
pip install -r ./libraries/Obfuscapk/src/requirements.txt
pip install -r ./libraries/maltorch/requirements.txt
pip install --no-deps git+https://github.com/androguard/androguard@v3.4.0a1
