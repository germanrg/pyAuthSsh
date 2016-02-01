#!/usr/bin/env python
 
import os
from colorama import init, Fore, Back, Style # easy-install colorama

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
	print(Back.WHITE + Style.BRIGHT + "                                                                      ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                  " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                  " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + Fore.RED + "                           pyAuthSsh.py                           " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + Fore.YELLOW + "                           -._.-**-._.-                           " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + Fore.GREEN + "                           by gNrg 2016                           " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                  " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "  " + Back.RESET + "                                                                  " + Back.WHITE + Style.BRIGHT + "  ")
	print(Back.WHITE + Style.BRIGHT + "                                                                      ")
	print("\n")

# This function shows menu options
def show_menu_options():
	print(Fore.YELLOW + "\t1 - )   " + Fore.RESET + "Show all SSH servers started in this host")
	print(Fore.YELLOW + "\t2 - )   " + Fore.RESET + "Show all accepted passwords and opened sessiones")
	print(Fore.YELLOW + "\t3 - )   " + Fore.RESET + "Show all closed sessions")
	print(Fore.YELLOW + "\t4 - )   " + Fore.RESET + "Show all ssh failed authentications")
	print(Fore.YELLOW + "\t5 - )   " + Fore.RESET + "Show all ssh not received identifications")
	print(Fore.YELLOW + "\t6 - )   " + Fore.RESET + "Exit")
	print("\n")
	option = raw_input(Fore.YELLOW + Style.BRIGHT + "   Choose one of this options: ")
	return option

# This function open, read and return the content of auth.log
def get_log():
	try:
		log = open(log_path, 'rt')
		text = log.read()
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Log file has been readed correctly")
	except IOError: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: File does not appear to exist.")
	print("\n\n")
	return text

# This function classify relevant lines on categories
def classify_entries(sshd_lines, servers_listening, opened_sessions, closed_sessions, auth_failures, no_identifications):
# Types of sshd lines analyzed:
#	- Server listening [Date - host - ip - port]
#	- Accepted password + sshd:session
#	- Received disconnect + sshd:session
#	- sshd:auth authentication failure [LogName - uid - euid - tty - ruser - rhost - user ]
#   - NEW: sshd[7748]: Did not receive identification string from X.X.X.X
	for entry in sshd_lines:
		if entry.find("Server listening") != -1: servers_listening.append(entry)
		if entry.find("Accepted password") != -1: opened_sessions.append(entry)
		if entry.find("Received disconnect") != -1: closed_sessions.append(entry)
		if entry.find("pam_unix(sshd:auth): authentication failure") != -1: auth_failures.append(entry)
		if entry.find("Did not receive identification") != -1: no_identifications.append(entry)

# This function shows local ssh daemons runned logged in /var/auth/auth.log
def get_servers(servers_listening):
	if len(servers_listening) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Servers listening have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no servers listening.\n")

	for server in servers_listening:
		output = '\t'
		fields = server.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		output += 'Server Host:\t' + str(fields[3])
		output += '\n\tServer up time:\t' 
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += date + "\n\t"
		output += "Listening on port: " + str(fields[10]) + "\n"
		print output

# This function shows failed authentications logged in /var/auth/auth.log
def get_auth_fails(auth_failures):
	''' Example auth.log line:
	Jan 31 16:53:59 nb200 sshd[15920]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=localhost  user=xxxx
	'''
	if len(auth_failures) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: authentication failures have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no authentication failures.\n")

	for fail in auth_failures:
		output = '\t'
		fields = fail.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		output += 'Failed attempt time:\t' 
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += date + "\n\t"
		info = str(fields[14]) + "\t" + str(fields[8]) + "\t" + str(fields[9]) + "\t" + str(fields[10]) + "\t" + str(fields[11]) + "\t" + str(fields[12]) + "\t" + str(fields[13]) + "\n"
		output += info
		print output

# This function shows opened sessions logged in /var/auth/auth.log
def get_opened_sessions(opened_sessions):
	''' Example auth.log line:
	Jan 31 16:53:48 nb200 sshd[15885]: Received disconnect from 127.0.0.1: 11: disconnected by user
	'''
	if len(opened_sessions) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Opened sessions have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no opened sessions.\n")

	for accepted_password in opened_sessions:
		output = '\t'
		fields = accepted_password.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += 'Open session date:\t' + date + "\n"
		info = "\tUser: " + str(fields[8]) + "\tIP: " + str(fields[10]) + "\tPort:" + str(fields[12]) + "\n"
		info += output
		print info

# This function shows opened sessions logged in /var/auth/auth.log
def get_closed_sessions(closed_sessions):
	''' Example auth.log line:
	Jan 31 16:53:48 nb200 sshd[15885]: Received disconnect from 127.0.0.1: 11: disconnected by user
	'''
	if len(closed_sessions) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Closed sessions have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no closeded sessions.\n")

	for accepted_password in closed_sessions:
		output = '\t'
		fields = accepted_password.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += 'Close session date:\t' + date + "\n"
		info = "\tIP: " + str(fields[8]) + "\n"
		info += output
		print info

# This function shows identifications not received logged in /var/auth/auth.log
def get_no_identification(no_identifications):
	''' Example auth.log line:
	Aug 19 06:28:43 izxvps sshd[5838]: Did not receive identification string from 59.151.37.10
	'''
	if len(no_identifications) > 0:
		print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: No received identifications have been loaded.\n")
	else: 
		print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no received identifications.\n")

	for identification in no_identifications:
		output = '\t'
		fields = identification.split(" ")
		fields = filter(lambda x: x!='', fields) # Remove blanks
		date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
		output += 'Log date:\t' + date + "\n"
		info = "\tDid not receive identification string from:\t" + str(fields[11]) + "\n"
		info += output
		print info


if __name__ == "__main__":

	init(autoreset = True) # Colorama autoreset to default on each print

	script_header()
	log = get_log() 

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
	classify_entries(sshd_lines, servers_listening, opened_sessions, closed_sessions, auth_failures, no_identifications)

	option = '0'
	while option:
		option = show_menu_options()
		script_header()
		# Process selected option
		if option == "1": get_servers(servers_listening)
		elif option == "2": get_opened_sessions(opened_sessions)
		elif option == "3": get_closed_sessions(closed_sessions)
		elif option == "4": get_auth_fails(auth_failures)
		elif option == "5": get_no_identification(no_identifications)
		elif option == "6": print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tThanks for using. Bye!\n\n\t" + Back.BLUE + "  " + Back.RESET + "\tgnrg@tuta.io\n\n"); break
		else:
			print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tIncorrect option. Try again!\n")
			option = '0'

"""
Jan 31 16:54:01 nb200 sshd[15920]: Failed password for gnrg from 127.0.0.1 port 38861 ssh2
Jan 31 16:54:07 nb200 sshd[15920]: message repeated 2 times: [ Failed password for gnrg from 127.0.0.1 port 38861 ssh2]
Jan 31 16:54:07 nb200 sshd[15920]: Connection closed by 127.0.0.1 [preauth]
Jan 31 16:54:07 nb200 sshd[15920]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=localhost  user=gnrg
"""

# Read about use of fail2ban for the detected intrussion attempts.