#!/usr/bin/python3

import sys
import socket
import re
import os
import time

# installed packages
from pwn import *
import argparse
import paramiko

# declare script path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# custom package
import pre_settings
import pre_ping_check
import pre_attacks
import pre_services_check

# displays only critical errors or important information
context.log_level = pre_settings.debug_critical

def restart_service(rhost, path):
    client = paramiko.SSHClient()

    # add -oHostKeyAlgorithms=+ssh-rsa
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    stdin, stdout, stderr = None, None, None

    # default metasploitable2 credential
    cred = 'msfadmin'
    
    # timeout for all paramiko.exec_command
    timeout = 60

    try:
        client.connect(rhost, username=cred, password=cred, timeout=timeout)
        
        if path != '/usr/bin/unrealircd':

            # restart service
            stdin, stdout, stderr = client.exec_command(f'{pre_settings.SUDO_PATH} {path} restart', timeout=timeout)

            # Pass the password to the sudo prompt
            stdin.write(f'{cred}\n')
            stdin.flush()

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
        
        else:
            # Run the command to get the PID of unrealircd
            stdin, stdout, stderr = client.exec_command(f'{pre_settings.PGREP_PATH} unrealircd', timeout=timeout)

            # Read the output of the command
            pid = stdout.read().decode().strip()

            if pid:
                stdin, stdout, stderr = client.exec_command(f'{pre_settings.SUDO_PATH} {pre_settings.KILL_PATH} {pid}', timeout=timeout)
                stdin.write(f'{cred}\n')
                stdin.flush()

            stdin, stdout, stderr = client.exec_command(f'{pre_settings.SUDO_PATH} {path}', timeout=timeout)

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            # handle empty first line
            check_error = re.search(r'booting IRCd', error)
            if check_error is not None:
                output = check_error.group(0)
                error = None
        
        if error:
            log.error(str(error))
            return False

        if output:
            return True
        
    except (paramiko.SSHException, paramiko.AuthenticationException, paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, socket.error) as e:
        # log.error(str(e))
        return False

    except (EOFError, pwnlib.exception.PwnlibException, ConnectionRefusedError, ValueError, Exception) as e:
        # log.error(str(e))
        return False
    
    except KeyboardInterrupt:
        sys.exit(0)
    
    finally:
        client.close()

def main():
    try:
        parser = argparse.ArgumentParser(description=pre_settings.print_argparse_desc('Services Availability Restarter'), epilog=f'{pre_settings.print_argparse_epilog(f"python3 {sys.argv[0]} --rhost 10.251.5.5 --rport 80")}')
        parser.add_argument('--rhost', help='Target IP', default='10.251.5.5')
        parser.add_argument('--rport', help='Target Port', type=int)
        args = parser.parse_args()

        rhost = args.rhost
        rport = args.rport
        
        if rport is None:
            # Handle the case where `rport` is not specified
            unique_ports = set()  # To store unique ports
            for key, value in pre_attacks.attacks.items():
                # Normalize `value['port']` to a set
                ports = {value['port']} if isinstance(value['port'], int) else set(value['port'])
                path = value['path']

                for port in ports:
                    # Skip duplicate ports
                    if port in unique_ports:
                        continue
                    unique_ports.add(port)

                    status_ping = pre_ping_check.check(rhost)
                    status_service_restart = restart_service(rhost, path)
                    status_service_post = pre_services_check.check(rhost, port)

                    print(pre_settings.print_status_service_restart(rhost, port, value['service'], status_ping, status_service_restart, status_service_post))
        else:
            # Handle the case where `rport` is specified
            status_ping = pre_ping_check.check(rhost)

            # Find the matching service name and path for the specified `rport`
            service = None
            path = None
            for key, value in pre_attacks.attacks.items():
                ports = {value['port']} if isinstance(value['port'], int) else set(value['port'])
                if rport in ports:
                    service = value['service']
                    path = value['path']
                    break

            if service and path:
                status_service_restart = restart_service(rhost, path)
                status_service_post = pre_services_check.check(rhost, rport)

                print(pre_settings.print_status_service_restart(rhost, rport, service, status_ping, status_service_restart, status_service_post))
            else:
                log.error("Invalid rport specified or service not found!")

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()