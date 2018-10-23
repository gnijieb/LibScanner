#!/usr/bin/env bash

mkdir -p cves
cd cves || exit 1
rm -f ./*.xml

readonly year=$(date +"%Y")
for ii in $(seq -f "%04g" 2002 "${year}")
do
    echo "Fetching CVE data for ${ii}..."
    wget -q "https://nvd.nist.gov/download/nvdcve-${ii}.xml.gz" || exit 1
    gunzip "nvdcve-${ii}.xml.gz" || exit 1
done

rm -f ./*.gz
