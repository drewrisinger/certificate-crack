#!/bin/bash

#NOTE: this script must be run from same directory as all .pem files. does not check subdirectories.

#decode each SSL certificate into the public key
openssl x509 -in $1 -pubkey -noout
