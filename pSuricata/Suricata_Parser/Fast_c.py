from Suricata_Parser.Suricata_Parser import Suricata_Parser
#    Folder          SuperClassFileName     SuperClassName

import sys,re,shutil

class Fast_c(Suricata_Parser):
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
			elif bool(re.match(r'^[0-9]{2}/[0-9]{2}/[0-9]{4}',line)) == True:# time
				time_hold, basic_time = (super(Fast_c, self).convert_time(line))
				time_hold+= "\n"
				self._timestamps.append(basic_time)
				try:url = http_d[basic_time]+"\n"
				except: url= "Not an HTTP Request\n"
				url_a.append(url)


			append_ready += 1

			if loop_prep == True:
				loop_prep = False
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
