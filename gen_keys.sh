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

if [ -n "$1" ]; then
  case "$1" in
    "clean")
      delete_keys server
      delete_keys client
      break
      ;;
    "server")
      generate_keys server
      break
      ;;
    "client")
      generate_keys client
      break
      ;;
    *)
      echo "Usage: $0 [server|client|clean]"
      echo "Generates key pairs for SSL"
      ;;
  esac
else
  generate_keys server
  generate_keys client
fi
