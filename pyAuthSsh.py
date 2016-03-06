#!/usr/bin/env python
#
# gnrg(at)tuta.io
#

import os, optparse
from SSHLogger import *

desc = """%prog by gNrg   -   
Simply script to get information from a given log file
about your SSH server. The scripts provides all info
if variable LOG_LEVEL has the value INFO configured.
You can save the given information in other file in
text format using -l <path_to_file> option. For more
information about script usage and options use -h. """
version = "%prog V0.1"
usage = "usage: %prog [-hspcfnkrb] [-o|-d] [-l <file>]"
header = """
    +----------------------------------------------------+
    |                                                    |
    |                    sshLogger.py                    |
    |                    -._.-**-._.-                    |
    |                      by  gNrg                      |
    |                                                    |
    +----------------------------------------------------+\n
"""

if __name__ == "__main__":
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

    if opts.o_flag and opts.nd_flag:
        parser.error("Option '-o' and option '-d' are incompatible. Choose only one of them.\n")
        parser.print_help()
        exit(-1)

    options = opts.s_flag or opts.ap_flag or opts.cs_flag or opts.fa_flag or opts.ni_flag or opts.pk_flag or opts.r_flag or opts.b_flag
    if not options:
    	parser.error("Select at least one of this options: [-spcfnkrb].\n")
    	parser.print_help()
    	exit(-1)

    os.system("clear")
    print header
    ### Add inputs for these paths
    logger = SSHLogger('/var/log/auth.log', '/etc/ssh/sshd_config')
    raw_input("\tPress enter to continue...\n")
    os.system("clear")
    print header
    print logger.get_preview()
    raw_input("\tPress enter to continue...\n")
    os.system("clear")
    print header

    output = []
    if opts.s_flag:
        s = logger.get_servers()
        if len(s) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no servers listening.\n")
    	else:
            print("  +  [[ OK ]]: Servers listening have been loaded. (" + str(len(s)) + ")\n")
            output.append(s)
    if opts.ap_flag:
        os = logger.get_opened_sessions()
        if len(os) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no opened sessions.\n")
        else:
            print("  +  [[ OK ]]: Opened sessions have been loaded. (" + str(len(os)) + ")\n")  
            output.append(os)
    if opts.cs_flag:
        cs = logger.get_closed_sessions()
        if len(cs) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no closeded sessions.\n")
        else:
            print("  +  [[ OK ]]: Closed sessions have been loaded. (" + str(len(cs)) + ")\n")
            output.append(cs)
    if opts.fa_flag:
        fa = logger.get_auth_failures()
        if len(fa) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no authentication failures.\n")
        else:
            print("  +  [[ OK ]]: Authentication failures have been loaded. (" + str(len(fa)) + ")\n")
            output.append(fa)
    if opts.ni_flag:
        ni = logger.get_no_identifications()
        if len(ni) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no received identifications.\n")
        else:
            print("  +  [[ OK ]]: No received identifications have been loaded. (" + str(len(ni)) + ")\n")
            output.append(ni)
    if opts.pk_flag:
        pk = logger.get_accepted_public_keys()
        if len(pk) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no accepted public keys.\n")
        else:
            print("  +  [[ OK ]]: Accepted public keys have been loaded. (" + str(len(pk)) + ")\n")
            output.append(pk)
    if opts.r_flag: 
        rm = logger.get_repeated_messages()
        if len(rm) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no repeated messages.\n")
        else:
            print("  +  [[ OK ]]: Repeated messages have been loaded. (" + str(len(rm)) + ")\n")
            output.append(rm)
    if opts.b_flag:
        b = logger.get_break_in_attempts()
        if len(b) == 0:
            print("  x  [[ ERROR ]]: It seems like there is no break in attempts.\n")
        else:
            print("  +  [[ OK ]]: Break in attempts have been loaded. (" + str(len(b)) + ")\n")            
            print("\tUnfortunately this break-in attempts are a very common occurrence.")
            print("\tIt is maybe an automated attack which is using well known usernames")
            print("\t(as 'root' or anyone created by common apps) to try and break into")
            print("\tyour system. The message it doesn't mean that you have been hacked")
            print("\tjust that someone tried.\n")
            print("\tAnyway, if you can improve your openssh-server configuration visit:\n")
            print("\t\t http://tiny.cc/p91r8x\n\n")
            raw_input("\tPress any key to continue...")
            output.append(b)
    log_text = ''
    for t in output:
        for l in t:
            if not opts.nd_flag: print l
            if opts.o_flag: raw_input("Press enter to show next entry... \n")
            if opts.log_file: log_text += l + '\n'

    ### Check log file path
    if opts.log_file: 
        resp = logger.create_file(log_file, log_text)
        if resp == 1: 
            print "  +  [[ OK ]]: The file has been saved in: " + log_file + '\n'
        elif resp == -1: 
            print "  x  [[ ERROR ]]: An error has ocurred. File can't be created.\n"
            print("  x               - Check if the path is correct.")
            print("  x               - Check if do you have permissions for create files in this folder.")
            print("  x               - Then, try again.")