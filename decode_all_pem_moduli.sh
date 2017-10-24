#!/bin/bash

#check if the sub directories exist. if not, then create them.
if [ ! -d "modulus" ]; then
  mkdir modulus
fi


#decode each SSL certificate into the modulus

#better way, using parallel
find -maxdepth 1 -name \*.pem -type f | parallel --no-notice "./par_decode_all_pem_modulus.sh {} >> ./modulus/all_keys.moduli"

echo "DONE DECODING SSL PEM MODULII"
