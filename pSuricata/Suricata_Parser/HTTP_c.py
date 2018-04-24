from Suricata_Parser.Suricata_Parser import Suricata_Parser
#    Folder          SuperClassFileName     SuperClassName

import sys,re

class HTTP_c(Suricata_Parser):
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


			elif bool(re.match(r'^(\s?)/',line)) == True:
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
