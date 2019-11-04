#!/usr/bin/env bash

mkdir -p cves
cd cves || exit 1
rm -f ./*.xml

readonly year=$(date +"%Y")
for ii in $(seq -f "%04g" 2002 "${year}")
do
    echo "Fetching CVE data for ${ii}..."
    wget -q "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-${ii}.json.gz" || exit 1
    gunzip "nvdcve-1.0-${ii}.json.gz" || exit 1
done

rm -f ./*.gz
