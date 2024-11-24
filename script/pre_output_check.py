#!/usr/bin/python3

import sys
import os

# installed packages
from pwn import *
import paramiko

# declare script path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# custom package
import pre_settings
import pre_ping_check
import pre_services_check
import pre_attacks
import pre_services_restart

# displays only critical errors or important information
context.log_level = pre_settings.debug_critical

def check(rhost):
    try:
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

            # Execute command to verify connection
            stdin, stdout, stderr = client.exec_command("cat /tmp/root.txt")
            output = stdout.read().decode().strip()

            if 'root' in output:
                return output
            else:
                return ''
            
        except (paramiko.SSHException, paramiko.AuthenticationException, socket.timeout, socket.error, Exception) as e:
            return False
        
        finally:
            client.close()

    except KeyboardInterrupt:
        sys.exit(0)