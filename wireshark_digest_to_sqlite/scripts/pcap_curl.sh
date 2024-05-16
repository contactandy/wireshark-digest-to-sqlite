#!/bin/bash

# if you set location by $HOME, it will differ if sudo or not. 
export SSLKEYLOGFILE=/tmp/sslkeys.log
tcpdump -i wlp3s0 -w curl.pcap &
sleep .05s
# use http1.1 and tlsv1.3
curl --http1.1 --tlsv1.3 https://www.example.com > /dev/null
# use http1.1 and tlsv1.3 - set curve to secp256r1 to avoid hello retry request
curl --http1.1 --tlsv1.3 --curves secp256r1 https://www.example.net > /dev/null
# use http1.1 and tlsv1.2
curl --http1.1 --tlsv1.2 --tls-max 1.2 https://www.example.net > /dev/null
# use http 
curl --http2 https://www.example.org > /dev/null
sleep 1s
pkill --signal SIGINT tcpdump
mv /tmp/sslkeys.log ./
# note: a list of -o perferences can be found under Wireshark->Preferences->Advanced
tshark -r curl.pcap -n -2 -T json --no-duplicate-keys -o tls.keylog_file:sslkeys.log > curl.json
