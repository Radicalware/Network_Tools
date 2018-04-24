#!/usr/bin/env python3

import os,sys
import fcntl; fcntl.fcntl(1, fcntl.F_SETFL, 0) # line by DEKHTIARJonathan 
# fcntl is for users who have multi-line PS1 output

from Suricata_Parser import Suricata_Parser, HTTP_c, Fast_c

def helper(white, green):
	print (white +'''
	# Author : Scourge from Radicalware.net
	# Licence: GNU GPLv3
	# Program: pSuricata.py v1
	# Purpose: Helps parse out Suricata read pcap files

	Suricata Parser

	usage: '''+green+'''
	$> psuricata.py -r pcap_file_name.pcap Exploit "-> 192.168.204.137"'''+white+'''
	
	Use the command above if you don't have logs stored for that pcap already
	The command will search for if either "Exploit" or "-> 192.168.204.137" pops
	'''+green+'''
	$> psuricata.py -u -g Network URI -a -v 18:19:24.107376'''+white+'''

	This command does not read a pcap file so it will used the one stored
	It uses boolean and '-a' so both 'Network' and 'URI' must be found
	also, there is a '-v' which means that the timestamp 18:19:24.107376
	will be omitted. The '-g' was needed because we had a '-v' in use.

	arguments: 
	-r <pcap file>   = use this to update or parse your suricata pcap data
	-a               = Grep uses results from bool 'and' instead of default bool 'or'
	-g               = Greps the trailing array args until the next '-v'
	-v               = vGreps the trailing array args until the next '-g'
	-u               = Searches only for querys that have a url (HTTP traffic)

	That command will show the results that include the two arguments 
	in the suricata output as an and statment.

	Be sure to make sure your interface matches and the http is enabled
	/etc/suricata/suricata.yaml

	More detail on installing for ubuntu can be found here'''+green+'''

	Note: The rapid7 blog will have you download 3.0.2, be sure to instead get
	      the latest version
	https://blog.rapid7.com/2017/02/14/how-to-install-suricata-nids-on-ubuntu-linux/'''+white+'''
	http://suricata.readthedocs.io/en/latest/install.html#install-binary-packages

	Note: search color highlighting is Case Sensitive, however, 
		  the grep search itself is not case sensitive.

			''');quit()



def f(): # use this for debugging
	print('hit')
	quit()


http_log = HTTP_c.HTTP_c()
#          FileName.ClassName
http_log.parse_http()

fast_log = Fast_c.Fast_c(http_log.http_d())
fast_log.parse_fast()

if len(fast_log.fast_s()) > 1:
	print(fast_log.fast_s())
else:
	print('Your query did not return any results')
