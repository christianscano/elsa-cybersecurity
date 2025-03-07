#!/bin/bash

# Install the required packages
pip install -r requirements.txt
pip install -r ./libraries/Obfuscapk/src/requirements.txt
pip install -r ./libraries/maltorch/requirements.txt
pip install --no-deps androguard==3.4.0a1
