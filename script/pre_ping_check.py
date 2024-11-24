#!/usr/bin/python3

import subprocess
import sys

# installed packages
from pwn import *
import argparse

# declare script path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# custom package
import pre_settings

# displays only critical errors or important information
context.log_level = pre_settings.debug_critical

def check(rhost):
    try:
        # /usr/bin/ping -c 1 <ip>
        response = subprocess.run([pre_settings.PING_PATH, '-c', '1', rhost], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)

        # Check the return code, 0 means success
        return response.returncode == 0
    
    except KeyboardInterrupt:
        sys.exit(0)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        log.error(str(e))
        sys.exit(1)
    except (subprocess.TimeoutExpired, pwnlib.exception.PwnlibException, subprocess.SubprocessError, Exception) as e:
        # log.error(str(e))
        return False

def main():
    try:
        parser = argparse.ArgumentParser(description=pre_settings.print_argparse_desc('ICMP Ping Checker'), epilog=f'{pre_settings.print_argparse_epilog(f"python3 {sys.argv[0]} --rhost 10.251.5.5")}')
        parser.add_argument('--rhost', help='Target IP', default='10.251.5.5')
        args = parser.parse_args()

        rhost = args.rhost

        print(pre_settings.print_status_ping_main(rhost, check(rhost)))

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()