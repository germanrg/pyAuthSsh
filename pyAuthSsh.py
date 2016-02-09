#!/usr/bin/env python
 
import os, sys
from colorama import init, Fore, Back, Style # easy-install colorama

# This script has been optimized for black/dark terminal backgrounds.
""" Types of sshd lines analyzed:
	- [MONTH] [DAY] [TIME] [HOST] sshd: Server listening on [IP] port [PORT].
	- [MONTH] [DAY] [TIME] [HOST] sshd: Accepted password for [USER] from [IP] port [PORT] ssh2
	- [MONTH] [DAY] [TIME] [HOST] sshd: Received disconnect from [IP] x: disconnected by [USER]
	- [MONTH] [DAY] [TIME] [HOST] sshd: pam_unix(sshd:auth): authentication failure; [LOGNAME] [UID] [EUID] [TTY] [RUSER] [RHOST] [USER]
    - [MONTH] [DAY] [TIME] [HOST] sshd: Did not receive identification string from [IP]
    - [MONTH] [DAY] [TIME] [HOST] sshd: Accepted publickey for [USER] from [IP] port [PORT] ssh2: [KEY]
	- [MONTH] [DAY] [TIME] [HOST] sshd: message repeated [X] times: [ Failed password for [USER] from [IP] port [PORT] ssh2]
	- [MONTH] [DAY] [TIME] [HOST] sshd: reverse mapping checking getaddrinfo for [ADDR. INFO] [IP] failed - POSSIBLE BREAK-IN ATTEMPT!
"""
""" Available formating colorama constants:
		Fore: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
		Back: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
		Style: DIM, NORMAL, BRIGHT, RESET_ALL
"""

# Variables
log_path = '/var/log/auth.log'

months = {"Jan" : 1,
          "Feb" : 2,
          "Mar" : 3,
          "Apr" : 4,
          "May" : 5,
          "Jun" : 6,
          "Jul" : 7,
          "Aug" : 8,
          "Sep" : 9,
          "Oct" : 10,
          "Nov" : 11,
          "Dec" : 12,
}

# This function shows the script header
def script_header():
	os.system("clear")
	print(Back.WHITE + Style.BRIGHT + "                                                                              ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                          " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                          " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + Fore.RED + "                               pyAuthSsh.py                               " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + Fore.YELLOW + "                               -._.-**-._.-                               " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + Fore.GREEN + "                               by gNrg 2016                               " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                          " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                          " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "                                                                              ")
	print("\n")

# This function shows menu options
def show_menu_options():
	print(Fore.YELLOW + Style.BRIGHT + "\t1 - )   " + Style.NORMAL + Fore.RESET + "Show all times the SSH server is up")
	print(Fore.YELLOW + Style.BRIGHT + "\t2 - )   " + Style.NORMAL + Fore.RESET + "Show all Accepted passwords")
	print(Fore.YELLOW + Style.BRIGHT + "\t3 - )   " + Style.NORMAL + Fore.RESET + "Show all Closed sessions")
	print(Fore.YELLOW + Style.BRIGHT + "\t4 - )   " + Style.NORMAL + Fore.RESET + "Show all ssh failed authentications")
	print(Fore.YELLOW + Style.BRIGHT + "\t5 - )   " + Style.NORMAL + Fore.RESET + "Show all ssh not received identifications")
	print(Fore.YELLOW + Style.BRIGHT + "\t6 - )   " + Style.NORMAL + Fore.RESET + "Show all accepted public keys")
	print(Fore.YELLOW + Style.BRIGHT + "\t7 - )   " + Style.NORMAL + Fore.RESET + "Show all repeated messages")
	print(Fore.YELLOW + Style.BRIGHT + "\t8 - )   " + Style.NORMAL + Fore.RESET + "Show all possible break-in attempts")		
	print(Fore.YELLOW + Style.BRIGHT + "\t9 - )   " + Fore.RED + "Exit")
	print("\n")
	option = raw_input(Fore.YELLOW + Style.BRIGHT + "   Choose one of this options: ")
	return option

# This function open, read and print information about /etc/ssh/sshd_config
def get_sshd_config():
	sshd_conf_text = ''
	log_level = ''
	syslog = ''
	try:
		sshd_conf_file = open("/etc/ssh/sshd_config", 'rt')
		sshd_conf_text = sshd_conf_file.read()
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: /etc/ssh/sshd_config file has been readed correctly\n\n")
	except IOError: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: /etc/ssh/sshd_config file not found!\n\n")
		sys.exit(0)

	# Detect LogLevel and SyslogFacility attributes and get it
	for line in sshd_conf_text.split("\n"):
		if line.find("SyslogFacility") != -1:
			syslog = line
		elif line.find("LogLevel") != -1:
			log_level = line

	ll = []
	sl = []
	for x in syslog.split(" "):
		sl.append(x)
	for y in log_level.split(" "):
		ll.append(y)
	
	# If not detected lines raise an error.
	if len(ll) == 0 or len(sl) == 0:
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: /etc/ssh/sshd_config hasn't got LogLevel or SyslogFacility attributes!\n\n")
		sys.exit(0)

	# Check if LogLevel is INFO and check if SyslogFacility is AUTH
	if sl[1] != 'AUTH':
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: SSH daemon log are not in /var/log/auth.log!\n\n")
		sys.exit(0)
	else:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: SSH daemon log are in /var/log/auth.log\n\n")
	
	if ll[1] != 'INFO':
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: Your DebugLevel is not supported by the script!\n\n")
		print("\tYou can change the attribute DebugLevel to 'INFO' on /etc/ssh/sshd_config.")
		sys.exit(0)
	else:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Your SSH DebugLevel is INFO\n\n")

# This function open, read and return the content of auth.log
def get_log():
	try:
		log = open(log_path, 'rt')
		text = log.read()
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: /var/log/auth.log file has been readed correctly")
	except IOError: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: /var/log/auth.log file not found!")
	print("\n\n")
	return text

# This function classify relevant lines on categories
def classify_entries(sshd_lines, servers_listening, opened_sessions, closed_sessions, auth_failures, no_identifications, accepted_public_keys, repeated_messages, break_in_attempts):
	for entry in sshd_lines:
		if entry.find("Server listening") != -1: servers_listening.append(entry)
		elif entry.find("Accepted password") != -1: opened_sessions.append(entry)
		elif entry.find("Received disconnect") != -1: closed_sessions.append(entry)
		elif entry.find("pam_unix(sshd:auth): authentication failure") != -1: auth_failures.append(entry)
		elif entry.find("Did not receive identification") != -1: no_identifications.append(entry)
		elif entry.find("Accepted publickey") != -1: accepted_public_keys.append(entry)
		elif entry.find("message repeated") != -1: repeated_messages.append(entry)
		elif entry.find("POSSIBLE BREAK-IN ATTEMPT") != -1: break_in_attempts.append(entry)

def log_preview(servers_listening, opened_sessions, closed_sessions, auth_failures, no_identifications, accepted_public_keys, repeated_messages, break_in_attempts):
	script_header()
	print "\tServers listening:\t\t" + str(len(servers_listening))
	print "\tOpened sessions:\t\t" + str(len(opened_sessions))
	print "\tClosed sessions:\t\t" + str(len(closed_sessions))
	print "\tAuthentication failures:\t" + str(len(auth_failures))
	print "\tNo identifications:\t\t" + str(len(no_identifications))
	print "\tAccepted Public Keys:\t\t" + str(len(accepted_public_keys))
	print "\tRepeated Messages:\t\t" + str(len(repeated_messages))
	print "\tBreak in attempts:\t\t" + str(len(break_in_attempts)) + "\n\n"
	raw_input("\tPress any key to continue...")

# This function shows local ssh daemons runned logged in /var/auth/auth.log
def get_servers(servers_listening):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: Server listening on [IP] port [PORT].
	'''
	if len(servers_listening) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Servers listening have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no servers listening.\n")

    """print(Fore.YELLOW + Style.BRIGHT + "\t1 - )   " + Style.NORMAL + Fore.RESET + "Show entries one by one")
	print(Fore.YELLOW + Style.BRIGHT + "\t2 - )   " + Style.NORMAL + Fore.RESET + "Show all entries")
	print(Fore.YELLOW + Style.BRIGHT + "\t3 - )   " + Style.NORMAL + Fore.RESET + "Show all entries and save as a text file")
	print(Fore.YELLOW + Style.BRIGHT + "\t4 - )   " + Style.NORMAL + Fore.RESET + "Don't show anything but save as a text file")		
	print(Fore.YELLOW + Style.BRIGHT + "\t9 - )   " + Fore.RED + "Back to main menu")
	print("\n")
	option = raw_input(Fore.YELLOW + Style.BRIGHT + "   Choose one of this options: ")"""
	

	for server in servers_listening:
		fields = server.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		output = '\tServer Host:\t' + str(fields[3]) + '\n\tServer up time:\t' 
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += date + "\n\t"
		output += "Listening on port: " + str(fields[10]) + "\n"
		print output

	raw_input("\tPress any key to continue...")

# This function shows opened sessions logged in /var/auth/auth.log
def get_opened_sessions(opened_sessions):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: Accepted password for [USER] from [IP] port [PORT] ssh2
	'''
	if len(opened_sessions) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Opened sessions have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no opened sessions.\n")

	for accepted_password in opened_sessions:
		fields = accepted_password.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output = '\tOpen session date:\t' + date + "\n"
		info = "\tUser: " + str(fields[8]) + "\tIP: " + str(fields[10]) + "\tPort:" + str(fields[12]) + "\n"
		info += output
		print info

# This function shows opened sessions logged in /var/auth/auth.log
def get_closed_sessions(closed_sessions):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: Received disconnect from [IP] x: disconnected by [USER]
	'''
	if len(closed_sessions) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Closed sessions have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no closeded sessions.\n")

	for accepted_password in closed_sessions:
		fields = accepted_password.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output = '\tClose session date:\t' + date + "\n"
		info = "\tIP: " + str(fields[8]) + "\n" + output
		print info

# This function shows failed authentications logged in /var/auth/auth.log
def get_auth_fails(auth_failures):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: pam_unix(sshd:auth): authentication failure; [LOGNAME] [UID] [EUID] [TTY] [RUSER] [RHOST] [USER]
	'''
	if len(auth_failures) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: authentication failures have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no authentication failures.\n")

	for fail in auth_failures:
		fields = fail.split(" ")		
		fields = filter(lambda x: x!='', fields) # Remove blanks
		output = '\tFailed attempt time:\t' 
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += date + "\n\t"
		if len(fields) < 15: info = "user=None\t"
		else: info = str(fields[14]) + "\t"
		info += str(fields[8]) + "\t" + str(fields[9]) + "\t" + str(fields[10]) + "\t" + str(fields[11]) + "\t" + str(fields[12]) + "\t" + str(fields[13]) + "\n"
		output += info
		print output

# This function shows identifications not received logged in /var/auth/auth.log
def get_no_identification(no_identifications):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: Did not receive identification string from [IP]
	'''
	if len(no_identifications) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: No received identifications have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no received identifications.\n")

	for identification in no_identifications:
		fields = identification.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output = '\tLog date:\t' + date + "\n"
		info = "\tDid not receive identification string from:\t" + str(fields[11]) + "\n" + output
		print info

# This function shows all accepted public keys logged in /var/auth/auth.log
def get_accepted_public_keys(accepted_public_keys):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: Accepted publickey for [USER] from [IP] port [PORT] ssh2: [KEY]
	'''
	if len(accepted_public_keys) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Accepted public keys have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no accepted public keys.\n")

	for pubkey in accepted_public_keys:
		fields = pubkey.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output = '\tLog date:\t' + date + "\n"
		info = "\tUser: " + str(fields[8]) + "\tIP: " + str(fields[10]) + "\tPort:" + str(fields[12]) + "\n\tKey: "
		# Add key to output
		for x in fields[14:]:
			info += str(x)

		info += "\n" + output
		print info

# This function shows all repeated messages logged in /var/auth/auth.log
def get_repeated_messages(repeated_messages):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: message repeated [X] times: [ Failed password for [USER] from [IP] port [PORT] ssh2]
	'''
	if len(repeated_messages) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Repeated messages have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no repeated messages.\n")

	for message in repeated_messages:
		fields = message.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output = '\tLog date:\t' + date + "\n"
		info = "\tRepetitions: " + str(fields[7]) + "\n\tMessage:" 
		# Add repeated message to output
		for x in fields[10:18]:
			info += " " + str(x)

		info += "\n" + output
		print info

# This function shows all break in attempts logged in /var/auth/auth.log
def get_break_in_attempts(break_in_attemptse):
	''' Example auth.log line:
	[MONTH] [DAY] [TIME] [HOST] sshd: reverse mapping checking getaddrinfo for [ADDR. INFO] [IP] failed - POSSIBLE BREAK-IN ATTEMPT!
	'''
	if len(break_in_attempts) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Break in attempts have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no break in attempts.\n")

	print("\tUnfortunately this break-in attempts are a very common occurrence.")
	print("\tIt is maybe an automated attack which is using well known usernames")
	print("\t(as 'root' or anyone created by common apps) to try and break into")
	print("\tyour system. " + Back.WHITE + Fore.BLACK + "The message it doesn't mean that you have been hacked")
	print("\tjust that someone tried.\n")
	print(Fore.YELLOW + "\tAnyway, if you can improve your openssh-server configuration visit:\n")
	print(Back.BLUE + Fore.WHITE + "\t\t http://tiny.cc/p91r8x" + Back.RESET + Fore.RESET + "\n\n")

	raw_input("\tPress any key to continue...")

	for attempt in break_in_attempts:
		fields = attempt.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output = '\tLog date:\t' + date + "\n"
		info = "\tBreak in attempt: " + str(fields[12]) + "\n\t" 
		# Add log message to output
		for x in fields[5:12]:
			info += str(x) + " "

		info += "\n" + output
		print info

if __name__ == "__main__":

	init(autoreset = True) # Colorama autoreset to default on each print

	script_header()
	get_sshd_config()
	log = get_log()

	raw_input("\tAll files was loaded. Press any key to continue...")

	# Collecting SSHD related entries
	sshd_lines = []
	for line in log.split("\n"):
		if line.find("sshd") != -1:
			sshd_lines.append(line)

	servers_listening = []
	opened_sessions = []
	closed_sessions = []
	auth_failures = []
	no_identifications = []
	accepted_public_keys = []
	repeated_messages = []
	break_in_attempts = []

	classify_entries(sshd_lines, servers_listening, opened_sessions, closed_sessions, auth_failures, no_identifications, accepted_public_keys, repeated_messages, break_in_attempts)
	log_preview(servers_listening, opened_sessions, closed_sessions, auth_failures, no_identifications, accepted_public_keys, repeated_messages, break_in_attempts)

	option = '0'
	while option:
		script_header()
		option = show_menu_options()
		script_header()
		# Process selected option
		if option == "1": get_servers(servers_listening)
		elif option == "2": get_opened_sessions(opened_sessions)
		elif option == "3": get_closed_sessions(closed_sessions)
		elif option == "4": get_auth_fails(auth_failures)
		elif option == "5": get_no_identification(no_identifications)
		elif option == "6": get_accepted_public_keys(accepted_public_keys)
		elif option == "7": get_repeated_messages(repeated_messages)
		elif option == "8": get_break_in_attempts(break_in_attempts)
		elif option == "9": print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tThanks for using. Bye!\n\n\t" + Back.BLUE + "  " + Back.RESET + "\tgnrg@tuta.io\n\n"); break
		else:
			print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tIncorrect option. Try again!\n")
			option = '0'

# Read about use of fail2ban for the detected intrussion attempts.