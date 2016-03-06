#!/usr/bin/env python
#
# gnrg(at)tuta.io
#

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
          "Dec" : 12,}

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
        self.log_path = log_path
        self.sshd_path = sshd_path
        
        self.__check_sshd__()
        self.__check_log__()
        self.log_level = self.__get_log_level__()
        if self.log_level == 'INFO': print("  +  [[ OK ]]: LogLevel = INFO     ((sshd_conf file))\n")
        else: print("  x  [[ ERROR ]]: LogLevel != INFO     ((sshd_conf file))\n  x  This warning can cause errors.")

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
        ''' Check if a given sshd config file can be readed and LogLevel is setted to 'INFO'. '''
        try:
            self.sshd_file = open(self.sshd_path, 'rt')
            self.sshd_text = self.sshd_file.read()
            print("  +  [[ OK ]]: /etc/ssh/sshd_config file has been readed correctly\n")
        except IOError:
            print("  x  [[ ERROR ]]: /etc/ssh/sshd_config file not found!\n")
    def __check_log__(self):
        ''' Check if a given log file can be readed. '''
        try:
            self.log_file = open(self.log_path, 'rt')
            self.log_text = self.log_file.read()
            print("  +  [[ OK ]]: " + self.log_path + " file has been readed correctly\n")
        except IOError: 
            print("  x  [[ ERROR ]]: " + self.log_path + " file not found!\n")
    def __classify__(self):
        ''' Search and classify ssh log entries '''
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
    def __get_log_level__(self):
        ''' Return the log level information in sshd_config. '''
        ll = []
        for line in self.sshd_text.split("\n"):
            if line.find("LogLevel") != -1:
                log_level = line
        for x in log_level.split(" "):
            ll.append(x)
        if len(ll) == 0: return ''
        else: return ll[1] # Optimized for 'INFO' level
    def get_log(self):
        ''' Return string with complete log file text. '''
        return self.log_text
    def get_preview(self):
        ''' Return some relevant information string '''
        preview = "  +  Overview \n\n"
        preview += "\tServers listening:\t\t" + str(len(self.servers_listening)) + "\n"
        preview += "\tOpened sessions:\t\t" + str(len(self.opened_sessions)) + "\n"
        preview += "\tClosed sessions:\t\t" + str(len(self.closed_sessions)) + "\n"
        preview += "\tAuthentication failures:\t" + str(len(self.auth_failures)) + "\n"
        preview += "\tNo identifications:\t\t" + str(len(self.no_identifications)) + "\n"
        preview += "\tAccepted Public Keys:\t\t" + str(len(self.accepted_public_keys)) + "\n"
        preview += "\tRepeated Messages:\t\t" + str(len(self.repeated_messages)) + "\n"
        preview += "\tBreak in attempts:\t\t" + str(len(self.break_in_attempts)) + "\n"
        return preview
    def get_servers(self):
        ''' Return list with formatted log lines about servers up. Example log line: 
        [MONTH] [DAY] [TIME] [HOST] sshd: Server listening on [IP] port [PORT]. '''
        text = []
        if len(self.servers_listening) == 0:
            return text
        else: 
            for server in self.servers_listening:
                fields = server.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                output = '\tServer Host:\t' + str(fields[3]) + '\n\tServer up time:\t' 
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output += date + "\n\t" + "Listening on port: " + str(fields[10]) + "\n"
                text.append(output)
        return text
    def get_opened_sessions(self):
        ''' Return list with formatted log lines about opened sessions. Example log line: 
        [MONTH] [DAY] [TIME] [HOST] sshd: Accepted password for [USER] from [IP] port [PORT] ssh2'''
        text = []
        if len(self.opened_sessions) == 0:
            return text
        else:  
            for accepted_password in self.opened_sessions:
                fields = accepted_password.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tOpen session date: ' + date + "\n"
                info = "\tUser: " + str(fields[8]) + "\tIP: " + str(fields[10]) + "\tPort:" + str(fields[12]) + "\n"
                info += output
                text.append(info)
        return text
    def get_closed_sessions(self):
        ''' Return list with formatted log lines about closed sessions. Example log line: 
        [MONTH] [DAY] [TIME] [HOST] sshd: Received disconnect from [IP] x: disconnected by [USER] '''
        text = []
        if len(self.closed_sessions) == 0:
            return text
        else:            
            for accepted_password in self.closed_sessions:
                fields = accepted_password.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tClose session date:\t' + date + "\n"
                info = "\tIP: " + str(fields[8]) + "\n" + output
                text.append(info)
        return text
    def get_auth_failures(self):
        ''' Return list with formatted log lines about authentication failures. Example log line: 
        [MONTH] [DAY] [TIME] [HOST] sshd: pam_unix(sshd:auth): authentication failure; [LOGNAME] [UID] [EUID] [TTY] [RUSER] [RHOST] [USER] '''
        text = []
        if len(self.auth_failures) == 0:
            return text
        else:          
            for fail in self.auth_failures:
                fields = fail.split(" ")        
                fields = filter(lambda x: x!='', fields) # Remove blanks
                output = '\tFailed attempt time:\t' 
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output += date + "\n\t"
                if len(fields) < 15: info = "user=None\t"
                else: info = str(fields[14]) + "\t"
                info += str(fields[8]) + "\t" + str(fields[9]) + "\t" + str(fields[10]) + "\t\n\t" + str(fields[11]) + "\t" + str(fields[12]) + "\t" + str(fields[13]) + "\n"
                output += info
                text.append(output)
        return text
    def get_no_identifications(self):
        ''' Return list with formatted log lines about no identifications. Example log line:
        [MONTH] [DAY] [TIME] [HOST] sshd: Did not receive identification string from [IP] '''
        text = []
        if len(self.no_identifications) == 0:
            return text
        else: 
            for identification in self.no_identifications:
                fields = identification.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tLog time:\t' + date + "\n"
                info = "\tDid not receive identification string from:\t" + str(fields[11]) + "\n" + output
                text.append(info)
        return text
    def get_accepted_public_keys(self):
        ''' Return list with formatted log lines about accepted public keys. Example log line:
        [MONTH] [DAY] [TIME] [HOST] sshd: Accepted publickey for [USER] from [IP] port [PORT] ssh2: [KEY] '''
        text = []
        if len(self.accepted_public_keys) == 0:
            return text
        else: 
            for pubkey in self.accepted_public_keys:
                fields = pubkey.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tLog date:\t' + date + "\n"
                info = "\tUser: " + str(fields[8]) + "\tIP: " + str(fields[10]) + "\tPort:" + str(fields[12]) + "\n\tKey: "
                # Add key to output
                for x in fields[14:]:
                    info += str(x)
                info += "\n" + output
                text.append(info)
        return text
    def get_repeated_messages(self):
        ''' Return list with formatted log lines about repeated messages. Example log line:
        [MONTH] [DAY] [TIME] [HOST] sshd: message repeated [X] times: [ Failed password for [USER] from [IP] port [PORT] ssh2] '''
        text = []
        if len(self.repeated_messages) == 0:
            return text
        else: 
            for message in self.repeated_messages:
                fields = message.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tLog date:\t' + date + "\n"
                info = "\tRepetitions: " + str(fields[7]) + "\n\tMessage:" 
                # Add repeated message to output
                for x in fields[10:18]:
                    info += " " + str(x)
                info += "\n" + output
                text.append(info)
        return text
    def get_break_in_attempts(self):
        ''' Return list with formatted log lines about possible break-in attempts. Example log line:
        [MONTH] [DAY] [TIME] [HOST] sshd: reverse mapping checking getaddrinfo for [ADDR. INFO] [IP] failed - POSSIBLE BREAK-IN ATTEMPT! '''
        text = []
        if len(self.break_in_attempts) == 0:
            return text
        else: 
            for attempt in self.break_in_attempts:
                fields = attempt.split(" ")
                fields = filter(lambda x: x!='', fields) # Remove blanks
                date = str(fields[2]) + " - " + str(fields[1]) + "/" + str(months[fields[0]])
                output = '\tLog date:\t' + date + "\n"
                info = "\tBreak in attempt: " + str(fields[12]) + "\n\t" 
                # Add log message to output
                for x in fields[5:12]:
                    info += str(x) + " "
                info += "\n" + output
                text.append(info)
        return text
    def create_file(self, file, text, mode = 'a'):
        ''' Create a new file and write given text on it. Return -1 (Error) or 1 (Ok). '''
        try:
            new_file = open(file, mode)
            new_file.write(text)
            new_file.close()
            return 1
        except: return -1