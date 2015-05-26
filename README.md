# nmap2csv
A script to parse the xml results file of an nmap scan and create a separate csv file for each host with that hosts TCP and UDP port results.

Your nmap scan must be run with the -oX or -oA flags in order to produce the necessary XML formatted results output file.

Requires: `gem install ox`

Usage: `ruby nmap2csv.rb nmap_results.xml`
