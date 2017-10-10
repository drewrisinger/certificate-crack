#!/bin/bash

#NOTE: this script must be run from same directory as all .pem files. does not check subdirectories.

#each of these commands will take >1 hour to run fully on dataset of > 100k. Comment out one you don't want.
./decode_all_pem_full.sh &
./decode_all_pem_pub.sh &

echo "DONE DECODING SSL PEM"
