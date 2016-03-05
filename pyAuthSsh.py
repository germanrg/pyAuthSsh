#!/usr/bin/env python
#
# gnrg(at)tuta.io
#

import os, optparse
from colorama import init, Fore, Back, Style # easy-install colorama
from SSHLogger import *

desc = """Description of %prog. gNrg."""
version='%prog v 0.1'
usage = "usage: %prog [-hspcfnkrb] [-o|-d] [-l <file>]"

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

if __name__ == "__main__":
    init(autoreset = True) # Colorama autoreset to default on each print

    parser = optparse.OptionParser(description = desc, version = version, usage = usage)
    parser.add_option("-s", "--server-up", action="store_true",
                        dest="servers_flag", default=False,
                        help="Show all times the SSH server has been launched")
    parser.add_option("-p", "--acc-passwords", action="store_true",
                        dest="accepted_pass_flag", default=False,
                        help="Show accepted passwords")
    parser.add_option("-c", "--closed-sessions", action="store_true",
                        dest="closed_sessions_flag", default=False,
                        help="Show closed sessions")
    parser.add_option("-f", "--failed-auth", action="store_true",
                        dest="failed_auth_flag", default=False,
                        help="Show failed authentications")
    parser.add_option("-n", "--no-idents", action="store_true",
                        dest="no_ident_flag", default=False,
                        help="Show SSH no received identifications")
    parser.add_option("-k", "--public-keys", action="store_true",
                        dest="keys_flag", default=False,
                        help="Show accepted public keys")
    parser.add_option("-r", "--repeat", action="store_true",
                        dest="repeat_flag", default=False,
                        help="Show repeated messages")
    parser.add_option("-b", "--break-in", action="store_true",
                        dest="breaks_flag", default=False,
                        help="Show break-in attempts")

    parser.add_option("-o", "--one-by-one", action="store_true",
                        dest="one_flag", default=False,
                        help="Display entries one by one")
    parser.add_option("-d", "--no-display", action="store_true",
                        dest="no_display_flag", default=False,
                        help="No display information in <stdout>")

    parser.add_option("-l", "--log", dest="log_file",
                        default="", type="string", metavar='<FILE>', 
                        help="Save output in a log file")

    (opts, args) = parser.parse_args()

    if opts.one_flag and opts.no_display_flag:
        parser.error("Option '-o' and option '-d' are incompatible. Choose only one of them.\n")
        parser.print_help()
        exit(-1)

    if opts.servers_flag: print 'servers flag'
    if opts.accepted_pass_flag: print 'accepted pass flag'
    if opts.closed_sessions_flag: print 'closed session flag'
    if opts.failed_auth_flag: print 'failed auth flag'
    if opts.no_ident_flag: print 'no ident flag'
    if opts.keys_flag: print 'keys flag'
    if opts.repeat_flag: print 'repeat flag'
    if opts.breaks_flag: print 'breaks flag'
    if opts.one_flag: print 'one flag'
    if opts.no_display_flag: print 'no display flag'
    if opts.log_file: print opts.log_file

    script_header()
    logger = SSHLogger('/var/log/auth.log', '/etc/ssh/sshd_config')
    raw_input("\tPress enter to continue...")

    option = '0'
    while option:
        if option != '-1': script_header()
        option = show_menu_options()
        script_header()
        # Process selected option
        if option == "1": logger.get_servers()
        elif option == "2": logger.get_opened_sessions()
        elif option == "3": logger.get_closed_sessions()
        elif option == "4": logger.get_auth_failures()
        elif option == "5": logger.get_no_identifications()
        elif option == "6": logger.get_accepted_public_keys()
        elif option == "7": logger.get_repeated_messages()
        elif option == "8": logger.get_break_in_attempts()
        elif option == "9": print("\t" + Back.GREEN + Style.BRIGHT + "  " + Back.RESET + "\tThanks for using. Bye!\n\n\t" + Back.BLUE + "  " + Back.RESET + "\tgnrg@tuta.io\n\n"); break
        else:
            print("\t" + Back.RED + Style.BRIGHT + "  " + Back.RESET + "\tIncorrect option. Try again!\n")
            option = '-1'