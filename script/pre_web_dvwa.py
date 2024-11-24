#!/usr/bin/python3

import sys
import re
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
import pre_services_check
import pre_services_restart

# displays only critical errors or important information
context.log_level = pre_settings.debug_critical

def reset(rhost, rport, attacks):
    try:
        status_ping = pre_ping_check.check(rhost)
        status_service_pre = pre_services_check.check(rhost, rport)

        if not status_service_pre:
            log.info(pre_settings.print_status_service_cleanup(rport, attacks['service'], status_service_pre, 'pre'))
            status_pre_service_restart = pre_services_restart.restart_service(rhost, attacks["path"])
            time.sleep(3)

        status_service_pre = pre_services_check.check(rhost, rport)

        status_service_restart = False
        status_service_post = status_service_pre

        if status_service_pre:
            url = f'http://{rhost}:{rport}/dvwa/setup.php'
            try:
                r = requests.get(url, timeout=3)
                if r.status_code == 200:
                    r = requests.post(url, timeout=3, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data={'create_db': 'Create / Reset Database'}, allow_redirects=True)
                    if r.status_code == 200:
                        success = re.search('Setup successful', r.text)
                        if success is not None:
                            status_service_restart = True
                            status_service_post = pre_services_check.check(rhost, rport)

                            return True

            except (requests.exceptions.RequestException, requests.exceptions.Timeout, Exception) as e:
                return False

            return False

        else:
            return False

    except KeyboardInterrupt:
        sys.exit(0)

def login(rhost, rport):
    session = requests.Session()
    try:
        r = session.post( f'http://{rhost}:{rport}/dvwa/login.php', headers={'Content-Type': 'application/x-www-form-urlencoded'}, data={'username': 'admin', 'password': 'password', 'Login': 'Login'}, allow_redirects=False, timeout=3)
        
        if r.headers.get('Location') == 'index.php':
            session.cookies.set('security', 'low', domain=f'{rhost}', path='/dvwa')
        
        return session
    
    except (requests.exceptions.RequestException, requests.exceptions.Timeout, Exception) as e:
        return False

    except KeyboardInterrupt:
        sys.exit(0)


def main():
    try:
        attacks = pre_attacks.attacks.get('sqli')

        parser = argparse.ArgumentParser(description=pre_settings.print_argparse_desc('DVWA Reset'), epilog=f'{pre_settings.print_argparse_epilog(f"python3 {sys.argv[0]} --rhost 10.251.5.5")}')
        parser.add_argument('--rhost', help='Target IP', default='10.251.5.5')
        args = parser.parse_args()

        rhost = args.rhost
        rport = attacks['port']

        print(pre_settings.print_status_dvwa_restart(rhost, rport, attacks['service'], pre_ping_check.check(rhost), reset(rhost, rport, attacks), pre_services_check.check_http(rhost, rport)))

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()