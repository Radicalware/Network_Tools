import sys,os,re,copy,shutil

class Suricata_Parser(object):
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
		if bool(re.search(r'Suricata 4.0.[0-9]([0-9]?)',tester)) == False:
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
				os.system('sudo suricata -c /etc/suricata/suricata.yaml --runmode autofp -r '+pcap_file_name)
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

