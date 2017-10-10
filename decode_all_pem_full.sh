#!/bin/bash

#check if the sub directories exist. if not, then create them.
if [ ! -d "fulltext" ]; then
  mkdir fulltext
fi


#decode each SSL certificate into the public key and full text
#for file in *.pem
#do
  #openssl x509 -in $file -text > ./fulltext/$file.full
  #openssl x509 -in $file -pubkey -noout > ./pub/$file.pub
#done

#better way, using parallel
find -maxdepth 1 -name \*.pem -type f | parallel --no-notice "./par_decode_all_pem_full.sh {} > ./fulltext/{.}.full.pem"

echo "DONE DECODING SSL PEM FULL"
