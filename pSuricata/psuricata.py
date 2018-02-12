#!/usr/bin/env python3

import os,sys,re,copy,shutil

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

	That command will show the results that inclue the two arguments 
	in the suricata output as an and statment.

	Be sure to make sure your interface matches and the http is enabled
	/etc/suricata/suricata.yaml

	More detail on installing for ubuntu can be found here'''+green+'''
	https://blog.rapid7.com/2017/02/14/how-to-install-suricata-nids-on-ubuntu-linux/'''+white+'''

	Note: search color highlighting is Case Sensitive, however, 
		  the grep search itself is not case sensitive.

			''');quit()



def f(): # use this for debugging
	print('hit')
	quit()


class Setup(object):
	def __init__(self, arguments):

		self.red    = '\033[1;31m'
		self.white  = '\033[1;37m'
		self.yellow = '\033[1;33m'
		self.pink   = '\033[1;35m'
		self.green  = '\033[1;32m'

		if len(sys.argv) > 1:
			if (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
				helper(self.white, self.green)

		try:    self.ss = shutil.get_terminal_size().columns
		except: self.ss = 0

		self.arguments = arguments
		self.grep  =[]
		self.vgrep =[]

		self.g_and = False # opposed to "grep or" = Default
		self.g_url = False # don't only search for http packets

		tester = os.popen('suricata').read()
		if bool(re.search('Suricata 4.0.3',tester)) == False:
			print("Suricata 4.0.3 was not found in your path\nsudo apt-get install suricata"); quit()

		parse_pcap = False
		for arg in self.arguments:
			if parse_pcap == True:
				pcap_file_name = arg
				break
			if arg == '-r':
				parse_pcap = True

		if parse_pcap == True:
			arguments.remove('-r')
			arguments.remove(pcap_file_name)
			try:
				os.system('sudo suricata -c /etc/suricata/suricata.yaml -r '+pcap_file_name)
			except:
				print('Your pcap file "'+pcap_file_name+'" was not found')
				quit()


	def parse_args(self):
		def arg_exist(def_arg, arguments,del_arg):
			truth = False
			for arg in arguments:
				if arg == def_arg:
					truth = True
					if del_arg == True: arguments.remove(def_arg)
					break
			return truth, arguments
					

		if (self.__class__.__name__) == "HTTP_c" or 1 == 1: 
			arguments = copy.copy(self.arguments)

			self.g_and, arguments = arg_exist('-a', arguments,True)
			self.g_url, arguments = arg_exist('-u', arguments,True)

			if arg_exist('-v',arguments,False)[0] == False and arg_exist('-g',arguments,False)[0] == False:
				self.grep = arguments[1:len(arguments):]
			elif arg_exist('-v',arguments,False)[0] == True and arg_exist('-g',arguments,False)[0] == False:
				arguments.remove('-v')              
				self.vgrep = arguments[1:len(arguments):]
			elif arg_exist('-v',arguments,False)[0] == False and arg_exist('-g',arguments,False)[0] == True:
				arguments.remove('-g')
				self.grep = arguments[1:len(arguments):]
			elif arg_exist('-v',arguments,False)[0] == True and arg_exist('-g',arguments,False)[0] == True:
				set_v = False
				set_g = False
				for arg in arguments:
					if arg == '-v':
						set_v = True
					elif arg == '-g':
						set_g = True
					elif set_v == True: 
						self.vgrep.append(arg)
					elif set_g == True:
						self.grep.append(arg)
				
				arguments.remove('-v')
				arguments.remove('-g')

		#print(self.grep);print(self.vgrep);f()


	def convert_time(self,time_stamp_inp):
		months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sept','Oct','Nov','Dec']
		if bool(re.search(r'\[\*\*\]',time_stamp_inp)):
			time_stamp_inp = re.sub(r'\s*\[\*\*\].*','',time_stamp_inp)

		month,day,year = time_stamp_inp.split('/')

		month = (int(month)-1)
		for i_month in months:
			if i_month  == months[month]:
				month = i_month
				break

		wireshark_time = ('frame.time == "'+(str(month) + ' ' + day + ', '+year).replace('-',' ')).strip()+'"'
		asm_time = ((str(month) + ' ' + day + ', '+year).replace('-',' ')).strip()
		return(wireshark_time,asm_time)


class Fast_c(Setup):
	def __init__(self,http_d):
		super().__init__(sys.argv)

		self._priority = []
		self._exploit = []
		self._classification = []
		self._com = []
		self._src_ip = []
		self._dst_ip = []
		self._timestamps = []
		self._fast_d =  {}
		self._http_d = http_d
		self._fast_s = ''
		self._url = []

		super(Fast_c,self).parse_args()
		try:
			self._fast_file = open('/var/log/suricata/fast.log','r').read()
		except:
			print('Your file "/var/log/suricata/fast.log" was not found')
			print('Use the "-r" with a pcap file to creat your first time log')
			quit()


	def parse_fast(self):
		http_d = self._http_d
		content = re.findall(re.compile(r'(?<=\[\*\*\]).*|^.*(?=\[\*\*\])',re.M),self._fast_file)
		time_stamps = re.findall(re.compile(r'^(.+?)(?=\s)',re.M),self._fast_file)


		n_content = []
		for i in content:
			n_content.append(re.sub(r' \[[0-9]\:[0-9]{7}\:[0-9]{1,3}\] ','',i))

		content = n_content
		new_content = []
		red_on = True

		for i in content:
			if bool(re.search(r'\[\*\*\]',i)):
				date,attack_type = i.split('[**]')
				new_content.append(date+"\n")
				new_content.append(attack_type)
			else:
				new_content.append(i+"\n")

		content = ''.join(new_content)
		content = re.sub(r'\[Classification\:','\n[Classification:', content)
		content = re.sub(r'\[Priority\:','\n[Priority:', content)
		content = re.sub(re.compile(r'\{UDP\}'),'\n{UDP}', content)
		content = re.sub(re.compile(r'\{TCP\}'),'\n{TCP}', content)

		#content = re.sub(r'\n\n$','\n',content).strip()
		content = content.strip()
		content = content.split("\n")
	

		# time > exploit > classification > priority > ip
		# ip > priority > classification > exploit > time
		ip_hold = ''
		priority_hold = ''
		classification = ''
		exploit_hold = ''
		time_hold = ''
		new_content = []
		loop_prep = False   
		url_a = []


		append_ready = 0
		loop_count = 0
		sep = (self.red + '='*self.ss + "\n" + self.white)

		for line in content:
			if bool(re.search(r'[0-9a-zA-Z]',line)) == False:
				append_ready -= 1
			elif bool(re.search(r'^\[Classification|^\[Priority|^\{TCP\}|^\{UDP\}',line)) == False \
			and bool(re.match(r'^[0-9]{2}/[0-9]{2}/[0-9]{4}',line)) == False:
				exploit_hold =  line + "\n"
				self._exploit.append(exploit_hold)
			elif bool(re.search(r'\{TCP\}|\{UDP\}',line)):
				self._com += line
				IPs= re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',line)
				self._src_ip.append(IPs[0])
				self._dst_ip.append(IPs[1])
				ip_hold =  line + "\n"
				loop_prep = True
			elif bool(re.search(r'^\[Classification',line)):
				self._classification.append(line)
				classification = line + "\n"
			elif bool(re.search(r'^\[Priority',line)):
				self._priority.append(line)
				priority_hold = line 
			elif bool(re.match(r'^[0-9]{2}/[0-9]{2}/[0-9]{4}',line)) == True:
				time_hold, basic_time = (super(Fast_c, self).convert_time(line))
				time_hold+= "\n"
				self._timestamps.append(basic_time)
				try:url = http_d[basic_time]+"\n"
				except: url= "Not an HTTP Request\n"
				url_a.append(url)


			append_ready += 1

			if append_ready == 4:
				append_ready = 0
				loop_count += 1

				# ip > priority > classification > exploit > time
				new_content = sep
				new_content += ip_hold + priority_hold + classification + exploit_hold + time_hold + url
				new_content += sep
		
				grep_count = len(self.grep)
				grep_counter = 0

				if url != 'Not an HTTP Request\n' or self.g_url == False:
					search_grep = True
					if len(self.vgrep) > 0:
						for arg in self.vgrep:
							if bool(re.search(re.compile(arg, re.I|re.M),new_content)):
								search_grep = False;break

					if search_grep == True:
						if len(self.grep) == 0:
							self._fast_s +=  new_content
						elif int(len(self.grep)) > 0:
							highlight = True
							if self.g_and == True:
								for word in self.grep:
									if bool(re.search(re.compile(word, re.I), new_content)) == False:
										highlight = False; break
							else:
								for word in self.grep:
									if bool(re.search(re.compile(word, re.I), new_content)) == True:
										grep_counter += 1

								if grep_counter == 0:
									highlight = False

							if highlight == True:
								for word in self.grep: 
									if bool(re.search(re.compile(word,re.I),new_content)) == True:
										new_content = new_content.replace(word,self.green+word+self.white)
								self._fast_s += (new_content)
				
				new_content = ''
	
	# I wish python had ruby style setter/headers
	# I made these for easy to access for python panda parsing
	def fast_s(self):return self._fast_s
	def priority(self):return self._priority
	def classification(self):return self._classification
	def com(self):return self._com
	def src_ip(self):return self._src_ip
	def dst_ip(self):return self._dst_ip
	def timestamps(self):return self._timestamps
	def fast_d(self):return self._fast_d
	def fast_s(self):return self._fast_s
	def url(self):return self._url
	def fast_file(self):return self._fast_file

class HTTP_c(Setup):
	def __init__(self):
		# extra data for pandas
		# suricata grabs other info sucha s OS version and Browser
		# you can add those if you want

		super().__init__(sys.argv)

		self._timestamps = []
		self._domain = []
		self._url = []
		self._http_d =  {}
		super(HTTP_c,self).parse_args()
		try:
			self._http_file = open('/var/log/suricata/http.log','r').read()
		except:
			print('Your file "/var/log/suricata/http.log" was not found')
			print('Use the "-r" with a pcap file to creat your first time log')
			print('Also, make sure that your HTTP suricata packet capture is')
			print('set in your /etc/suricata/suricata.yaml')
			quit()

		

	def parse_http(self):
		http_file = self._http_file
		http_log = http_file.replace('\n','[**]').split('[**]')
		http_d = {} # will replace self._http_d
		n_http_log = []
		domain = ''
		url = ''
		http_time_stamp = ''
		
		for line in http_log:
			if bool(re.match(r'^[0-9]{2}/[0-9]{2}/[0-9]{4}',line)) == True:     
				stop = False
				http_time_stamp = line.split()[0]
				domain = line.split()[1] # split by comma won't work due to "<hostname unknown>"

				if domain == '<hostname': 
					domain = '<Unknown Hostname>'
				basic_time = (super(HTTP_c, self).convert_time(http_time_stamp))[1]
				self._timestamps.append(basic_time)
				self._domain.append(domain)
				n_http_log.append(http_time_stamp)


			elif bool(re.match(r'^\s/',line)) == True:
				path = re.sub(r';.*','',line).strip()
				url = domain + path
				self._url.append(url)
				http_d[basic_time] = url
		
		self._http_d = http_d

	# I wish python had ruby style setter/headers
	# I made these for easy to access for python panda parsing
	def timestamps(self):return self._timestamps
	def domain(self):return self._domain
	def url(self):return self._url
	def http_d(self):return self._http_d
	def http_file(self):return self._http_file

http_log = HTTP_c()
http_log.parse_http()

fast_log = Fast_c(http_log.http_d())
fast_log.parse_fast()

if len(fast_log.fast_s()) > 1:
	print(fast_log.fast_s())
else:
	print('Your query did not return any results')
