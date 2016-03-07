Usage: pyAuthSsh.py [-hspcfnkrb] [-o|-d] [-l <file>]

This is a simply script to get information from a given log file
about your SSH server. The scripts provides all info  if variable LOG_LEVEL
has the value INFO configured.  You can save the given information in other
file in  text format using -l <path_to_file> option. For more  information
about script usage and options use -h.

Options:

  --version               Show program's version number and exit
  
  -h, --help              Show this help message and exit
  

  SSH Options:
  
    -s, --server-up         Show all times the SSH server has been launched
    
    -p, --acc-passwords     Show accepted passwords
    
    -c, --closed-sessions   Show closed sessions
    
    -f, --failed-auth       Show failed authentications
    
    -n, --no-idents         Show SSH no received identifications
    
    -k, --public-keys       Show accepted public keys
    
    -r, --repeat            Show repeated messages
    
    -b, --break-in          Show break-in attempts
    

  Display Options:
  
    -o, --one-by-one        Display entries one by one
    
    -d, --no-display        No display information in <stdout>
    

  File Options:
  
    -l <FILE>, --log=<FILE> Save output in a log file


gNrg (at) tuta.io
