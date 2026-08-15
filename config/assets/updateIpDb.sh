#!/bin/bash


cd ~/pool/assets

wget -O Country-New.mmdb https://raw.githubusercontent.com/alecthw/mmdb_china_ip_list/release/Country.mmdb
#wget -O Country-New.mmdb https://github.com/Hackl0us/GeoIP2-CN/raw/release/Country.mmdb
if [[ -n Country-New.mmdb ]]; then
  mv Country-New.mmdb Country.mmdb
#  curl http://127.0.0.1:12580/task/updateGeoIP
fi