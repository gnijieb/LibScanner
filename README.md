# Simple Vulnerability Scanner

A tool to compare a package list to the National Vulnerability Database's CVE list and report on vulnerabilities found.

### Usage

Create a Python 3 virtual environment and install `requirements.txt`

Run `./download_cves.sh` to fetch vulnerability data from the NVD. Downloaded files will be placed in a `cves` directory in the current working directory.

Run `python3 ./cli.py installed-packages.txt cves/ -f yocto`. `installed-packages.txt` is output from our Yocto build, and `cves/` is the directory created above.

The tool will compare the package list to the NVD data and print results to stdout. Output is in the form of failing JUnit tests, for easy inclusion in a CI pipeline.

#### Origins

Originally sourced from https://github.com/DanBeard/LibScanner, brought up to Python 3, and stripped down to a subset of functionality needed by Vorne.
