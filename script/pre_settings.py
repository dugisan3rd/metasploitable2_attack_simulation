#!/usr/bin/python3

import sys
import os
import shutil

# declare script path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# color
####################################
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[33m'
BLUE = '\033[94m'
MAGENTA = "\033[35m"
BLACK = '\033[30m'

RESET = '\033[0m'
BOLD = '\033[1m'

RED_BACKGROUND = '\033[41m'
GREEN_BACKGROUND = '\033[102m'
####################################

# declare all binary
####################################
PING_PATH = shutil.which('ping') or '/usr/bin/ping'
HPING_PATH = shutil.which('hping3') or '/usr/sbin/hping3'
SUDO_PATH = shutil.which('sudo') or '/usr/bin/sudo'
PGREP_PATH = shutil.which('pgrep') or '/usr/bin/pgrep'
KILL_PATH = shutil.which('kill') or '/bin/kill'
NMAP_PATH = shutil.which('nmap') or '/usr/bin/nmap'
####################################

# debug level
####################################
debug_critical = 'critical'
debug_debug = 'debug'
debug_info = 'info'
####################################

# pretty print
####################################
def print_argparse_desc(text):
    return f'{RED_BACKGROUND}=== {BOLD}{text} ==={RESET}'

def print_argparse_epilog(text):
    return f'{BOLD}Example: {GREEN}{text}{RESET}'

def print_rhost_rport(rhost, rport):
    return f'[{BOLD}{YELLOW}{rhost}:{rport}{RESET}]'

def print_rhost(rhost):
    return f'[{BOLD}{YELLOW}{rhost}{RESET}]'

def print_status_plus(status):
    return f'[{GREEN}+{RESET}]' if status else f'[{RED}-{RESET}]'

def print_status_pass(status):
    return f'[{BOLD}{GREEN}PASS{RESET}]' if status else f'[{BOLD}{RED}FAIL{RESET}]'

def print_status_up(status):
    return f'[{BOLD}{GREEN}UP{RESET}]' if status else f'[{BOLD}{RED}DOWN{RESET}]'

def print_status_access(status):
    return f'[{BOLD}{GREEN}ACCESSIBLE{RESET}]' if status else f'[{BOLD}{RED}INACCESSIBLE{RESET}]'

def print_status_block(status):
    return f'[{BOLD}{GREEN}UNBLOCKED{RESET}]' if status else f'[{BOLD}{RED}BLOCKED{RESET}]'

def print_status_ping(status):
    return f'{BOLD}{BLUE}PING:{RESET}{print_status_up(status)}'

def print_status_ping_main(rhost, status):
    return f'{print_status_plus(status)}{print_rhost(rhost)} >> {print_status_ping(status)}'

def print_rport_service(rport, service):
    return f'{YELLOW}({rport}/{service.lower()}){RESET}'

def print_iteration_time(iteration, time):
    return f'{BOLD}{RED_BACKGROUND}=== ITERATION: {iteration} || TIME: {time} ==={RESET}'

def print_csv_time(csv,time):
    return f'{BOLD}{RED_BACKGROUND}=== CSV OUTPUT: {csv} || TIME: {time} ==={RESET}'

def print_status_service(rport, service, status):
    return f'{BOLD}{BLUE}SERVICE{RESET}{print_rport_service(rport, service)}:{print_status_up(status)}'

def print_status_service_access(rport, service, status):
    return f'{BOLD}{BLUE}SERVICE{RESET}{print_rport_service(rport, service)}:{print_status_access(status)}'

def print_status_service_check(rhost, rport, service, status_ping, status_service):
    return f'{print_status_plus(status_service)}{print_rhost_rport(rhost, rport)} >> {print_status_ping(status_ping)} - {print_status_service(rport, service, status_service)}'

def print_status_service_restart_check(rport, service, status):
    return f'{BOLD}{BLUE}RESTART{RESET}{print_rport_service(rport, service)}:{print_status_pass(status)}'

def print_status_dvwa_restart_check(rport, service, status):
    return f'{BOLD}{BLUE}DVWA-RESET{RESET}{print_rport_service(rport, service)}:{print_status_pass(status)}'

def print_status_service_restart(rhost, rport, service, status_ping, status_service_restart, status_service_post):
    return f'{print_status_plus(status_service_restart)}{print_rhost_rport(rhost, rport)} >> {print_status_ping(status_ping)} >> {(print_status_service_restart_check(rport, service, status_service_restart))} -> {print_status_service_access(rport, service, status_service_post)}'

def print_status_dvwa_restart(rhost, rport, service, status_ping, status_service_restart, status_service_post):
    return f'{print_status_plus(status_service_restart)}{print_rhost_rport(rhost, rport)} >> {print_status_ping(status_ping)} >> {(print_status_dvwa_restart_check(rport, service, status_service_restart))} -> {print_status_service_access(rport, service, status_service_post)}'

def print_status_service_cleanup(rport, service, status, pre):
    text = 'restarting' if pre.lower() == 'pre' else 'cleanup'
    return f'{print_status_service_access(rport, service, status)} -> {BOLD}{GREEN}{text.upper()}{RESET}'

def print_status_attack(rhost, rport, service, attack, attack_type, status_ping, status_service_pre, status_attack, status_service_post, remark):
    return f'{print_status_plus(status_attack)}{print_rhost_rport(rhost, rport)}[{BOLD}{MAGENTA}{attack_type.upper()}{RESET}] >> {print_status_ping(status_ping)} - {print_status_service(rport, service, status_service_pre)} >> {BOLD}{MAGENTA}{attack.upper()}{RESET} == {print_status_block(status_attack)} -> {print_status_service_access(rport, service, status_service_post)} -> {BOLD}{remark.upper()}{RESET}'

####################################