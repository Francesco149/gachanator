#!/bin/sh

wdir=$(dirname "$0")
autoflake \
  --imports=oscrypto,appdirs,pyasn1,push_receiver,tendo,gachanator \
  -ir "$wdir"
autopep8 --indent-size=2 -ri "$wdir"
