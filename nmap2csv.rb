#!/usr/bin/env ruby
#
# Author: Ryan LeViseur
#
# A script to parse the xml results file of an nmap scan and create a separate
# csv file for each host with that hosts TCP and UDP port results
#
# Your nmap scan must be run with the -oX or -oA flags in order to produce
# the necessary XML formatted results output file
#
# Requires: `gem install ox`
#
# Usage: ruby nmap2csv.rb nmap_results.xml
#
#

require 'ox'
require 'csv'
# require 'pry'

# give the user a status
puts "Parsing file now..."

class Parser < ::Ox::Sax
  def start_element(name)
    case name
      when :host
        @host = {}
        @addresses = []
        @ports = []
      when :address
        @address_object = {}
      when :port
        @port_object = {}
    end
    @current_node = name
  end

  def attr(name, value)
    case @current_node
      when :address
        # build our address object
        @address_object[name] = value
      when :port, :state, :service
        # build our port object
        @port_object[name] = value
    end

    # snag the command used to run this scan
    if name == :args
      @scan_command = value
    # snag the time when this scan was run
    elsif name == :startstr
      @scan_time = value
    end
  end

  def end_element(name)
    # add complete address object to list of addresses
    @addresses << @address_object if name == :address

    # add complete port object to list of ports
    @ports << @port_object if name == :port

    # keep cycling unless we've reached the end of the host element
    return unless name == :host

    # find the IPv4 IP address element and set :ip_address to it
    ip_index = @addresses.index { |a| a.has_value? 'ipv4' }
    @host[:ip_address] = @addresses[ip_index][:addr]

    # let the user know we aren't dead 
    puts "Processing Host: #{@host[:ip_address]}"

    # build our csv lines and output to user
    @ports.each do |port|
      puts "#{@host[:ip_address]},#{port[:portid]}/#{port[:protocol]},#{port[:name]},#{port[:state]},#{port[:reason]}" #.split(',')
    end

    # build filename for this host's results file
    filename = @host[:ip_address] + "_" + Time.parse(@scan_time).strftime("%Y%m%d@%H%M") + ".csv"

    # build our csv for this host
    CSV.open(filename, 'w') do |csv|
      csv << ['host', 'port', 'service', 'state', 'reason']

        @ports.each do |port|
          csv << "#{@host[:ip_address]},#{port[:portid]}/#{port[:protocol]},#{port[:name]},#{port[:state]},#{port[:reason]}".split(',')
        end

      csv << []
      csv << ["Scan Command: #{@scan_command}"]
    end
  end
end

handler = Parser.new()
Ox.sax_parse(handler, open(ARGV[0]))