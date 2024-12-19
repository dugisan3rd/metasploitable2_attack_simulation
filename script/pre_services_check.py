#!/usr/bin/python3

import sys
import socket
import os

# installed packages
from pwn import *
import argparse
import requests

# declare script path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# custom package
import pre_settings
import pre_ping_check
import pre_attacks

# displays only critical errors or important information
context.log_level = pre_settings.debug_critical

# some case ping DOWN but service UP
def check(rhost, rport):
    try:
        conn = remote(rhost, int(rport), timeout=5)
        banner = conn.recvline(timeout=2).decode('utf-8', errors='ignore')
        conn.close()
        return True
    except KeyboardInterrupt:
        sys.exit(0)
    except (EOFError, pwnlib.exception.PwnlibException, ConnectionRefusedError, socket.timeout, ValueError, Exception) as e:
        # log.error(str(e))
        return False
    
def check_http(rhost, rport):
    try:
        r = requests.get(f'http://{rhost}:{rport}', timeout=3)
        if r.status_code == 200 and 'dvwa' in str(r.text):
            return True
        else:
            return False
    except KeyboardInterrupt:
        sys.exit(0)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, Exception) as e:
        # log.error(str(e))
        return False

def main():
    try:
        parser = argparse.ArgumentParser(description=pre_settings.print_argparse_desc('Services Availability Checker'), epilog=f'{pre_settings.print_argparse_epilog(f"python3 {sys.argv[0]} --rhost 10.251.5.5 --rport 80")}')
        parser.add_argument('--rhost', help='Target IP', default='10.251.5.5')
        parser.add_argument('--rport', help='Target Port', type=int)
        args = parser.parse_args()

        rhost = args.rhost
        rport = args.rport
        
        if rport is None:
            unique_services = set()
            for key, value in pre_attacks.attacks.items():
                ports = value['port'] if isinstance(value['port'], set) else {value['port']}
                for rport in ports:
                    status_ping = pre_ping_check.check(rhost)
                    status_service = check(rhost, rport)
                    service_status = pre_settings.print_status_service_check(rhost, rport, value['service'], status_ping, status_service)
                    
                    # Add the service status to the set, which ensures only unique entries are added
                    if service_status not in unique_services:
                        unique_services.add(service_status)
                        print(service_status)
        else:
            # Check for the specific rport
            status_ping = pre_ping_check.check(rhost)
            status_service = check(rhost, rport)

            # Find the matching service name for the specified rport
            service_name = None
            for key, value in pre_attacks.attacks.items():
                ports = value['port'] if isinstance(value['port'], set) else {value['port']}
                if rport in ports:
                    service_name = value['service']
                    break
            
            if service_name is None:
                service_name = 'undefined'
            
            service_status = pre_settings.print_status_service_check(rhost, rport, service_name, status_ping, status_service)
            print(service_status)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()