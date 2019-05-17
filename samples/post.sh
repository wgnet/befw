#!/bin/sh
if [ ! -f ~/.pusher.conf  ]; then
  echo "Please create ~/.pusher.conf before proceed"
  exit 1
fi
if [ ! -x ./pusher.py ]; then
  echo "Please run this script from samples directory"
  exit 1
fi

./pusher.py add ssh tcp 22
./pusher.py cadd ssh_tcp_22 127.0.0.1/8 1
./pusher.py list


