import random

def generate_random_key(length):
    #Gera um número inteiro aleatório com base na quantidade de bits
    key_int = random.getrandbits(length * 8)
    print(key_int)
    #Converte o número inteiro em bytes e retorna a chave em formato hexadecimal
    key_bytes = key_int.to_bytes(length, byteorder='big')
    print(key_bytes)#Apagar
    return key_bytes.hex()

def lists_definition(text):
    text_list = []
    text_matriz = []
    for i in range(0, len(text), 2):
        text_list.append(text[i:i+2])
    for i in range(0, len(text_list), 4):
        text_matriz.append(text_list[i:i+4])
    return text_matriz

def plaintext_tohex(plaint):
    plaint_bytes = plaint.encode('utf-8')
    plaint_hex = plaint_bytes.hex()
    return plaint_hex

def padding_plaintext(plaint):
    lenght = sum(len(i) for i in plaint)
    byte_padding = hex(16 - (lenght%16)).replace("0x","")
    tamanho = len(plaint)
    missing_lists = 4 - (len(plaint)%4)
    for lista in plaint:
        if len(lista) < 4:
            lista.extend(['0'+byte_padding] * (4 - len(lista)))
    for i in range(missing_lists):
        lista = []
        lista.extend(['0'+byte_padding] * 4)
        plaint.append(lista)
    return plaint    

def aes_encryption(k, plaint):
    print("\nKey:")
    for i in key:
        print(i)
    print("\n\nPLaintext:")
    j=0
    for i in plaint:
        if (j != 4):
            j+=1
            print(i)
        else:
            print("\n")
            print(i)
            j=0

#Gerar uma chave de 128 bits aleatória
key = generate_random_key(16)
print(key)

while(1):
    print("\nOpções:\n1 - AES")
    op = input("Escolha a opção: ")
    if (op == '1'):
        print("Opções:\n1 - Cifração\n2 - Decifração")
        op_aes = input("Escolha a opção: ")
        if (op_aes == '1'):
            plaintext = input("Insira um texto: ")
            plaintext = plaintext_tohex(plaintext)
            plaintext = lists_definition(plaintext)
            plaintext = padding_plaintext(plaintext)
            key = lists_definition(key)
            print(plaintext)
            print(key)
            aes_encryption(key, plaintext)
    else:
        break
