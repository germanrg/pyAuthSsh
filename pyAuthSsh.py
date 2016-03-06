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

    if opts.s_flag: 
    	servers = logger.get_servers()
    if opts.ap_flag: 
    	op_sessions = logger.get_opened_sessions()
    if opts.cs_flag:
        cl_sessions = logger.get_closed_sessions()
    if opts.fa_flag:
        auth_failures = logger.get_auth_failures()
    if opts.ni_flag: logger.get_no_identifications()
    if opts.pk_flag: logger.get_accepted_public_keys()
    if opts.r_flag: logger.get_repeated_messages()
    if opts.b_flag: logger.get_break_in_attempts()
    if opts.o_flag: print 'one flag'
    if opts.nd_flag: print 'no display flag'
    if opts.log_file: print opts.log_file
'''
print("\tThanks for using. Bye!\n\n\tgnrg@tuta.io\n\n")
'''