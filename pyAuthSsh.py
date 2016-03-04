#!/usr/bin/env python
#
# gnrg(at)tuta.io
#

import os
from colorama import init, Fore, Back, Style # easy-install colorama
from SSHLogger import *

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