import random

def generate_random_key(length):
    # Gera um número inteiro aleatório com base na quantidade de bits
    key_int = random.getrandbits(length * 8)
    
    # Converte o número inteiro em bytes e retorna a chave em formato hexadecimal
    key_bytes = key_int.to_bytes(length, byteorder='big')
    print(key_bytes)
    return key_bytes.hex()

def aes_encryption(k, plaint):
    print()

# Gerar uma chave de 128 bits aleatória
key = generate_random_key(16)

while(1):
    op = input("Opções:\n1 - AES\nEscolha a opção: ")
    if (op == 1):
        op_aes = input("Opções:\n1 - Cifração\n2 - Decifração\nEscolha a opção: ")
        if (op_aes == 1):
            plaintext = input("Insira um texto: ")
            aes_encryption(key, plaintext)