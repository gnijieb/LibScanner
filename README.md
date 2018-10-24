# Simple Vulnerability Scanner

A tool to compare a package list to the National Vulnerability Database's CVE list and report on vulnerabilities found.

### Usage

Create a Python 3 virtual environment and install `requirements.txt`

Run `./download_cves.sh` to fetch vulnerability data from the NVD. Downloaded files will be placed in a `cves` directory in the current working directory.

Run `python3 ./cli.py installed-packages.txt cves/ out.html -f yocto`.

 -  `installed-packages.txt` is the package list output from our Yocto build
 -  `cves/` is the directory created above
 -  `out.html` is the report that will be generated
 -  `-f yocto` indicates that the package list is in the Yocto build history format
 -  `-t 3` [optional, default 3.0] sets the severity threshold for high vs. low priority in the report

The tool will compare the package list to the NVD data and print results to stdout. Output is an HTML report detailing the vulnerabilities found.

##### Origins

Originally sourced from [DanBeard/LibScanner](https://github.com/DanBeard/LibScanner), brought up to Python 3, and reworked for functionality needed by [Vorne](https://github.com/Vorne).
