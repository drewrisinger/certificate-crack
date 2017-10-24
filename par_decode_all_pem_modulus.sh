#!/bin/bash

#NOTE: this script must be run from same directory as all .pem files. does not check subdirectories.

#decode each SSL certificate into just the modulus
openssl x509 -modulus -noout < $1  | sed s/Modulus=// 