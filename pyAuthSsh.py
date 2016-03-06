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
                        dest="servers_flag", default=False,
                        help="Show all times the SSH server has been launched")
    ssh_opts.add_option("-p", "--acc-passwords", action="store_true",
                        dest="accepted_pass_flag", default=False,
                        help="Show accepted passwords")
    ssh_opts.add_option("-c", "--closed-sessions", action="store_true",
                        dest="closed_sessions_flag", default=False,
                        help="Show closed sessions")
    ssh_opts.add_option("-f", "--failed-auth", action="store_true",
                        dest="failed_auth_flag", default=False,
                        help="Show failed authentications")
    ssh_opts.add_option("-n", "--no-idents", action="store_true",
                        dest="no_ident_flag", default=False,
                        help="Show SSH no received identifications")
    ssh_opts.add_option("-k", "--public-keys", action="store_true",
                        dest="keys_flag", default=False,
                        help="Show accepted public keys")
    ssh_opts.add_option("-r", "--repeat", action="store_true",
                        dest="repeat_flag", default=False,
                        help="Show repeated messages")
    ssh_opts.add_option("-b", "--break-in", action="store_true",
                        dest="breaks_flag", default=False,
                        help="Show break-in attempts")
    display_opts.add_option("-o", "--one-by-one", action="store_true",
                        dest="one_flag", default=False,
                        help="Display entries one by one")
    display_opts.add_option("-d", "--no-display", action="store_true",
                        dest="no_display_flag", default=False,
                        help="No display information in <stdout>")
    file_opts.add_option("-l", "--log", dest="log_file",
                        default="", type="string", metavar='<FILE>', 
                        help="Save output in a log file")

    parser.add_option_group(ssh_opts)
    parser.add_option_group(display_opts)
    parser.add_option_group(file_opts)

    (opts, args) = parser.parse_args()

    if opts.one_flag and opts.no_display_flag:
        parser.error("Option '-o' and option '-d' are incompatible. Choose only one of them.\n")
        parser.print_help()
        exit(-1)

    # if no options: exit and error

    os.system("clear")
    print header
    ### Add inputs for these paths
    logger = SSHLogger('/var/log/auth.log', '/etc/ssh/sshd_config')
    raw_input("\tPress enter to continue...\n")

    if opts.servers_flag: 
    	servers = logger.get_servers()
    if opts.accepted_pass_flag: 
    	op_sessions = logger.get_opened_sessions()
    if opts.closed_sessions_flag:
        cl_sessions = logger.get_closed_sessions()
    if opts.failed_auth_flag:
        auth_failures = logger.get_auth_failures()
    if opts.no_ident_flag: logger.get_no_identifications()
    if opts.keys_flag: logger.get_accepted_public_keys()
    if opts.repeat_flag: logger.get_repeated_messages()
    if opts.breaks_flag: logger.get_break_in_attempts()
    if opts.one_flag: print 'one flag'
    if opts.no_display_flag: print 'no display flag'
    if opts.log_file: print opts.log_file
'''
print("\tThanks for using. Bye!\n\n\tgnrg@tuta.io\n\n")
'''