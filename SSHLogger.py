#!/usr/bin/env python

from colorama import init, Fore, Back, Style # easy-install colorama
import os

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

class SSHLogger:
    """ SSH Logging Manager:
    - [MONTH] [DAY] [TIME] [HOST] sshd: Server listening on [IP] port [PORT].
    - [MONTH] [DAY] [TIME] [HOST] sshd: Accepted password for [USER] from [IP] port [PORT] ssh2
    - [MONTH] [DAY] [TIME] [HOST] sshd: Received disconnect from [IP] x: disconnected by [USER]
    - [MONTH] [DAY] [TIME] [HOST] sshd: pam_unix(sshd:auth): authentication failure; [LOGNAME] [UID] [EUID] [TTY] [RUSER] [RHOST] [USER]
    - [MONTH] [DAY] [TIME] [HOST] sshd: Did not receive identification string from [IP]
    - [MONTH] [DAY] [TIME] [HOST] sshd: Accepted publickey for [USER] from [IP] port [PORT] ssh2: [KEY]
    - [MONTH] [DAY] [TIME] [HOST] sshd: message repeated [X] times: [ Failed password for [USER] from [IP] port [PORT] ssh2]
    - [MONTH] [DAY] [TIME] [HOST] sshd: reverse mapping checking getaddrinfo for [ADDR. INFO] [IP] failed - POSSIBLE BREAK-IN ATTEMPT!
    """
    
    log_path = ''
    log_text = ''
    sshd_path = ''
    sshd_text = ''
    lines = ''
    save_path = ''

    def __init__(self, log_path = '/var/log/auth.log', sshd_path = '/etc/ssh/sshd_config'):

        init(autoreset = True) # Colorama autoreset to default on each print

        self.log_path = log_path
        self.sshd_path = sshd_path
        
        self.__check_sshd__()
        self.__check_log__()

        self.servers_listening = []
        self.opened_sessions = []
        self.closed_sessions = []
        self.auth_failures = []
        self.no_identifications = []
        self.accepted_public_keys = []
        self.repeated_messages = []
        self.break_in_attempts = []

        self.__classify__()
    def __check_sshd__(self):
        try:
            self.sshd_file = open(self.sshd_path, 'rt')
            self.sshd_text = self.sshd_file.read()
            print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: /etc/ssh/sshd_config file has been readed correctly\n\n")
        except IOError:
            print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: /etc/ssh/sshd_config file not found!\n\n")
    def __check_log__(self):
        try:
            self.log_file = open(self.log_path, 'rt')
            self.log_text = self.log_file.read()
            print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: " + self.log_path + " file has been readed correctly")
        except IOError: 
            print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tError: " + self.log_path + " file not found!")
        print("\n\n")
    def __classify__(self):
        log_lines = []
        for line in self.log_text.split("\n"):
            if line.find("sshd") != -1:
                log_lines.append(line)

        for entry in log_lines:
            if entry.find("Server listening") != -1: self.servers_listening.append(entry)
            elif entry.find("Accepted password") != -1: self.opened_sessions.append(entry)
            elif entry.find("Received disconnect") != -1: self.closed_sessions.append(entry)
            elif entry.find("pam_unix(sshd:auth): authentication failure") != -1: self.auth_failures.append(entry)
            elif entry.find("Did not receive identification") != -1: self.no_identifications.append(entry)
            elif entry.find("Accepted publickey") != -1: self.accepted_public_keys.append(entry)
            elif entry.find("message repeated") != -1: self.repeated_messages.append(entry)
            elif entry.find("POSSIBLE BREAK-IN ATTEMPT") != -1: self.break_in_attempts.append(entry)

    def get_preview(self):
        preview = "\tServers listening:\t\t" + str(len(self.servers_listening)) + "\n"
        preview += "\tOpened sessions:\t\t" + str(len(self.opened_sessions)) + "\n"
        preview += "\tClosed sessions:\t\t" + str(len(self.closed_sessions)) + "\n"
        preview += "\tAuthentication failures:\t" + str(len(self.auth_failures)) + "\n"
        preview += "\tNo identifications:\t\t" + str(len(self.no_identifications)) + "\n"
        preview += "\tAccepted Public Keys:\t\t" + str(len(self.accepted_public_keys)) + "\n"
        preview += "\tRepeated Messages:\t\t" + str(len(self.repeated_messages)) + "\n"
        preview += "\tBreak in attempts:\t\t" + str(len(self.break_in_attempts)) + "\n\n"
        return preview
    def create_file(self, text):
        script_header()
        new_name = raw_input("\n\tEnter the output filename: ")
        new_path = raw_input("\n\tEnter complete path for output file without filename: ")
        if os.path.isdir(new_path):
            new_file = open(new_path + '/' + new_name, 'w+')
            new_file.write(text)
            new_file.close()
            print "\n\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + '\tThe file has been saved in:' 
            print '\n\t\t' + new_path + '/' + new_name + '\n'
        else: print "\n\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + '\tInvalid path.' + new_path + '\n'
    def get_log(self): return self.log_text
    def get_syslog_facility(self):
        sl = []
        for line in sshd_text.split("\n"):
            if line.find("SyslogFacility") != -1:
                syslog = line
        for x in syslog.split(" "):
            sl.append(x)
        if len(sl) == 0: return ''
        else: return sl[1]
    def get_log_level(self):
        ll = []
        for line in sshd_text.split("\n"):
            if line.find("LogLevel") != -1:
                log_level = line
        for x in log_level.split(" "):
            ll.append(x)
        if len(ll) == 0: return ''
        else: return ll[1] # Optimized for 'INFO' level

    def get_servers(self, save_as = ''):
        if len(self.servers_listening) == 0:
            print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no servers listening.\n")
            raw_input("\tPress enter to continue...")
        else: 
            print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Servers listening have been loaded. (" + str(len(self.servers_listening)) + ")\n")

            show = True
            one_by_one = False
            text_file = False
            show, one_by_one, text_file = entries_menu(show, one_by_one, text_file)

            text_to_file = ''
            # Print servers
            for server in self.servers_listening:
                fields = server.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                output = '\tServer Host:\t' + str(fields[3]) + '\n\tServer up time:\t' 
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output += date + "\n\t"
                output += "Listening on port: " + str(fields[10]) + "\n"
                text_to_file += output + '\n'
                if show: print output
                if one_by_one: raw_input("\n\tPress enter to continue...\n")
            if not one_by_one and show: raw_input("\n\tPress enter to continue...\n")
            # Save output in text file
            if text_file:
                if show: raw_input("\n\tPress enter to continue...\n")
                self.create_file(text_to_file)
                if option != '': raw_input("\n\tPress enter to continue...\n")
    def get_opened_sessions(self, save_as = ''):
        ''' Example auth.log line: [MONTH] [DAY] [TIME] [HOST] sshd: Accepted password for [USER] from [IP] port [PORT] ssh2'''
        if len(self.opened_sessions) == 0:
            print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tUps. It seems like there is no opened sessions.\n")
            raw_input("\tPress enter to continue...")
        else: 
            print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tOK: Opened sessions have been loaded.\n")            

            show = True
            one_by_one = False
            text_file = False
            show, one_by_one, text_file = entries_menu(show, one_by_one, text_file)

            text_to_file = ''
            for accepted_password in self.opened_sessions:
                fields = accepted_password.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tOpen session date:\t' + date + "\n"
                info = "\tUser: " + str(fields[8]) + "\tIP: " + str(fields[10]) + "\tPort:" + str(fields[12]) + "\n"
                info += output
                text_to_file += info + '\n'
                if show: print info
                if one_by_one: raw_input("\n\tPress enter to continue...\n")
            if not one_by_one: raw_input("\n\tPress enter to continue...\n")
            # Save output in text file
            if text_file:
                if show: raw_input("\n\tPress enter to continue...\n")
                self.create_file(text_to_file)
                if option != '': raw_input("\n\tPress enter to continue...\n")

    def get_closed_sessions(self, save_as = ''):
        return self.closed_sessions

    def get_auth_failures(self, save_as = ''):
        return self.auth_failures

    def get_no_identifications(self, save_as = ''):
        return self.no_identifications

    def get_accepted_public_keys(self, save_as = ''):
        return self.accepted_public_keys

    def get_break_in_attempts(self, save_as = ''):
        return self.break_in_attempts

    #def save_log_as(self, log = self.lo, new_path):
        # Save a new log file
        #pass

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

# This function shows entry options
def entries_menu(show, one_by_one, text_file):
    option = '0'
    while option:
        print(Fore.YELLOW + Style.BRIGHT + "\t1 - )   " + Style.NORMAL + Fore.RESET + "Show entries one by one")
        print(Fore.YELLOW + Style.BRIGHT + "\t2 - )   " + Style.NORMAL + Fore.RESET + "Show entries one by one and save as a text file")
        print(Fore.YELLOW + Style.BRIGHT + "\t3 - )   " + Style.NORMAL + Fore.RESET + "Show all entries")
        print(Fore.YELLOW + Style.BRIGHT + "\t4 - )   " + Style.NORMAL + Fore.RESET + "Show all entries and save as a text file")
        print(Fore.YELLOW + Style.BRIGHT + "\t5 - )   " + Style.NORMAL + Fore.RESET + "Don't show anything but save as a text file")        
        print(Fore.YELLOW + Style.BRIGHT + "\t6 - )   " + Fore.RED + "Back to main menu")
        print("\n")          
        option = raw_input(Fore.YELLOW + Style.BRIGHT + "   Choose one of this options: ")
        print("\n")        
        # Process selected option
        if option == "1": 
            one_by_one = True
        elif option == "2": 
            one_by_one = True
            text_file = True
        elif option == "3": 
            pass
        elif option == "4":
            text_file = True
        elif option == "5":
            show = False
            text_file = True
        elif option == "6": 
            show = False
            option = ''
        else:
            print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tIncorrect option. Try again!\n\n")
            show = False
            option = '0'
        if option != '0': option = ''
    return(show, one_by_one, text_file)

if __name__ == "__main__":

    init(autoreset = True) # Colorama autoreset to default on each print

    script_header()
    logger = SSHLogger()
    raw_input("\tAll files was loaded. Press enter to continue...")
    option = '0'
    while option:
        script_header()
        option = show_menu_options()
        script_header()
        # Process selected option
        if option == "1": logger.get_servers()
        elif option == "2": logger.get_opened_sessions()
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