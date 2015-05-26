# nmap2csv
A script to parse the xml results file of an nmap scan and create a separate csv file for each host with that hosts TCP and UDP port results.

Your nmap scan must be run with the -oX or -oA flags in order to produce the necessary XML formatted results output file.

Requires: `gem install ox`

Usage: `ruby nmap2csv.rb nmap_results.xml`


------
### DOM vs SAX for XML Parsing

I had an initial version of this script using DOM method for XML parsing. Here are some basic stats comparing it to this version
that uses a SAX parser instead.

#### Sample File:
17 hosts, 238MB

#### DOM
Execution Time: `435.21s user 5.99s system 98% cpu 7:27.24 total`
RAM Usage: ~3GB

#### SAX
Execution Time: `41.04s user 1.32s system 97% cpu 43.278 total`
RAM Usage: maxed out at 253.4MB
