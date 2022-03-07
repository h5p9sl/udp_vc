#!/bin/sh

ssl=$(which openssl)

generate_keys() {
  $ssl genrsa -out $1.pem
  $ssl req -new -newkey rsa -nodes -keyout $1.pem -out $1.csr
  $ssl x509 -req -days 365 -in $1.csr -signkey $1.pem -out $1.cert
}

delete_keys() {
  rm $1.pem $1.csr $1.cert
}

if ["$1" == "clean"]; then
  delete_keys server
  delete_keys client
fi

generate_keys server
generate_keys client

