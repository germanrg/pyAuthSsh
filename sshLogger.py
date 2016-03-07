#!/usr/bin/env python
#
# gnrg(at)tuta.io
#

import os, optparse
from SSHLogger import *

# Large string variables
header = """
    +----------------------------------------------------+
    |                                                    |
    |                    sshLogger.py                    |
    |                    -._.-**-._.-                    |
    |                      by  gNrg                      |
    |                                                    |
    +----------------------------------------------------+\n
"""
version = "%prog V0.1"
usage = "usage: %prog [-hspcfnkrb] [-o|-d] [-l <file>]"
desc = """%prog by gNrg   -   
Simply script to get information from a given log file
about your SSH server. The scripts provides all info
if variable LOG_LEVEL has the value INFO configured.
You can save the given information in other file in
text format using -l <path_to_file> option. For more
information about script usage and options use -h. """
breakin_message = """\tUnfortunately this break-in attempts are a very common occurrence.
\tIt is maybe an automated attack which is using well known usernames
\t(as 'root' or anyone created by common apps) to try and break into
\tyour system. The message it doesn't mean that you have been hacked
\tjust that someone tried.\n
\tAnyway, if you can improve your openssh-server configuration visit:\n
\t\t http://tiny.cc/p91r8x\n"""

def check_file_path(file):
    ''' Check if the file path given is a valid path. '''
    is_path = False
    for c in file:
        if c == '/': 
            is_path = True
            break
    if is_path:
        path = []
        for x in file.split('/'): path.append(x)
        path = path[1:-1] # Remove first blank and filename
        file_path = ''
        for x in path: file_path += '/' + x
        if os.path.isdir(file_path): return True
        else: return False
    else: 
        return True

def script_header(header):
    ''' Clear screen and print script header '''
    os.system("clear")
    print header

def error_message(message):
    print("  x  [[ ERROR ]] : " + message + "\n")

def succes_message(message):
    print("  +  [[ OK ]]: " + message + "\n")

if __name__ == "__main__":
    # Configure script options
    parser = optparse.OptionParser(description = desc, version = version, usage = usage)
    ssh_opts = optparse.OptionGroup(parser, 'SSH Options')
    display_opts = optparse.OptionGroup(parser, 'Display Options')
    file_opts = optparse.OptionGroup(parser, 'File Options')

    ssh_opts.add_option("-s", "--server-up", action="store_true",
                        dest="s_flag", default=False,
                        help="Show all times the SSH server has been launched")
    ssh_opts.add_option("-p", "--acc-passwords", action="store_true",
                        dest="ap_flag", default=False,
                        help="Show accepted passwords")
    ssh_opts.add_option("-c", "--closed-sessions", action="store_true",
                        dest="cs_flag", default=False,
                        help="Show closed sessions")
    ssh_opts.add_option("-f", "--failed-auth", action="store_true",
                        dest="fa_flag", default=False,
                        help="Show failed authentications")
    ssh_opts.add_option("-n", "--no-idents", action="store_true",
                        dest="ni_flag", default=False,
                        help="Show SSH no received identifications")
    ssh_opts.add_option("-k", "--public-keys", action="store_true",
                        dest="pk_flag", default=False,
                        help="Show accepted public keys")
    ssh_opts.add_option("-r", "--repeat", action="store_true",
                        dest="r_flag", default=False,
                        help="Show repeated messages")
    ssh_opts.add_option("-b", "--break-in", action="store_true",
                        dest="b_flag", default=False,
                        help="Show break-in attempts")
    display_opts.add_option("-o", "--one-by-one", action="store_true",
                        dest="o_flag", default=False,
                        help="Display entries one by one")
    display_opts.add_option("-d", "--no-display", action="store_true",
                        dest="nd_flag", default=False,
                        help="No display information in <stdout>")
    file_opts.add_option("-l", "--log", dest="log_file",
                        default="", type="string", metavar='<FILE>', 
                        help="Save output in a log file")

    parser.add_option_group(ssh_opts)
    parser.add_option_group(display_opts)
    parser.add_option_group(file_opts)

    (opts, args) = parser.parse_args()

    #Incompatible options
    if opts.o_flag and opts.nd_flag:
        parser.error("Option '-o' and option '-d' are incompatible. Choose only one of them.\n")
        parser.print_help()
        exit(-1)

    # Required options
    options = opts.s_flag or opts.ap_flag or opts.cs_flag or opts.fa_flag or opts.ni_flag or opts.pk_flag or opts.r_flag or opts.b_flag
    if not options:
    	parser.error("Select at least one of this options: [-spcfnkrb].\n")
    	parser.print_help()
    	exit(-1)

    # Getting sshd_conf and auth.log
    script_header(header)
    actual_log = raw_input("\nEnter ssh log file path [Default: /var/log/auth.log]: ")
    if not actual_log: actual_log = '/var/log/auth.log'
    server_config = raw_input("\nEnter sshd config file path [Default: /etc/ssh/sshd_config]: ")
    if not server_config: server_config = "/etc/ssh/sshd_config"

    # Create Logger
    script_header(header)
    logger = SSHLogger(actual_log, server_config)
    raw_input("\tPress enter to continue...\n")

    # Get an abstract of the information
    script_header(header)
    print logger.get_preview()
    raw_input("\tPress enter to continue...\n")
    script_header(header)

    # Processing options
    output = []
    if opts.s_flag:
        s = logger.get_servers()
        if len(s) == 0:
            error_message("It seems like there is no servers listening.")
    	else:
            succes_message("Servers listening have been loaded. (" + str(len(s)) + ")")
            output.append(s)
    if opts.ap_flag:
        ops = logger.get_opened_sessions()
        if len(ops) == 0:
            error_message("It seems like there is no opened sessions.")
        else:
            succes_message("Opened sessions have been loaded. (" + str(len(ops)) + ")")  
            output.append(ops)
    if opts.cs_flag:
        cs = logger.get_closed_sessions()
        if len(cs) == 0:
            error_message("It seems like there is no closeded sessions.")
        else:
            succes_message("Closed sessions have been loaded. (" + str(len(cs)) + ")")
            output.append(cs)
    if opts.fa_flag:
        fa = logger.get_auth_failures()
        if len(fa) == 0:
            error_message("It seems like there is no authentication failures.")
        else:
            succes_message("Authentication failures have been loaded. (" + str(len(fa)) + ")")
            output.append(fa)
    if opts.ni_flag:
        ni = logger.get_no_identifications()
        if len(ni) == 0:
            error_message("It seems like there is no received identifications.")
        else:
            succes_message("No received identifications have been loaded. (" + str(len(ni)) + ")")
            output.append(ni)
    if opts.pk_flag:
        pk = logger.get_accepted_public_keys()
        if len(pk) == 0:
            error_message("It seems like there is no accepted public keys.")
        else:
            succes_message("Accepted public keys have been loaded. (" + str(len(pk)) + ")")
            output.append(pk)
    if opts.r_flag: 
        rm = logger.get_repeated_messages()
        if len(rm) == 0:
            error_message("It seems like there is no repeated messages.")
        else:
            succes_message("Repeated messages have been loaded. (" + str(len(rm)) + ")")
            output.append(rm)
    if opts.b_flag:
        b = logger.get_break_in_attempts()
        if len(b) == 0:
            error_message("It seems like there is no break in attempts.")
        else:
            succes_message("Break in attempts have been loaded. (" + str(len(b)) + ")")            
            print breakin_message
            raw_input("\tPress any key to continue...\n")
            output.append(b)
    log_text = ''
    # Show output
    for t in output:
        for l in t:
            if not opts.nd_flag: print l
            if opts.o_flag: raw_input("\tPress enter to show next entry... \n")
            if opts.log_file: log_text += l + '\n'
    # Write output into a file
    write_mode = 'a'
    if opts.log_file:
        if check_file_path(opts.log_file):
            if os.path.isfile(opts.log_file):
                overwrite = raw_input("  -  The given file already exists.\n  -  Do you want overwrite the existing file?[y/N]: ")
                if overwrite == 'y' or overwrite == 'Y':
                    write_mode = 'w'
            resp = logger.create_file(opts.log_file, log_text, write_mode)
        else: resp = -1
        if resp == 1: 
            succes_message("The file has been saved in: " + opts.log_file)
        elif resp == -1: 
            message = "An error has ocurred. File can't be created.\n"
            message += "  x               - Check if the path is correct.\n"
            message += "  x               - Check if do you have permissions for create/overwrite files in this folder.\n"
            message += "  x               - Then, try again.\n"
            error_message(message)