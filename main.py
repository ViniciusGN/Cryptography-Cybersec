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

def print_list(lista):
    for elements in zip(*lista):
        j=0
        for element in elements:
            if j==4:
                j=0
                print(end='   ')
            else:
                j+=1
            print(element, end=' ')
        print()

def generate_roundkey(k, round):
    print()

def xor_hex(byte1, byte2):
    int1 = int(byte1, 16)
    int2 = int(byte2, 16)
    result = int1^int2
    return hex(result)[2:]

def generate_roundkey(k, r):
    
    if r==0:
        return k
    
    s_box = [
            ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76'],
            ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
            ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
            ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
            ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
            ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
            ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
            ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
            ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
            ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
            ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
            ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
            ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
            ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
            ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
            ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
            ]
    
    #Round constant 128 bits
    rcon = ['8d', '01', '02', '04', '08', '10', '20', '40', '80', '1b', '36']
    
    
    w = []
    for i in range(len(k[3])):
        w.append(k[3][i])
    
    #ROT_WORD
    first_element = k[3][0]
    for i in range(1,len(k[3]),1):
        w[i-1] = k[3][i]
    w[3] = first_element
    
    #SUB_WORD
    for x in range(len(k[3])):
        byte = w[x]
        i = int(byte[0],16)
        j = int(byte[1],16)
        w[x] = s_box[i][j]
    
    #Round constant
    round_const = [rcon[r],'00','00','00']
    for i in range(len(k[3])):
        w[i] = xor_hex(w[i], round_const[i])
    print(w)
    
    #Expansion key: Primeiro faz o xor entre w e k[0] 
    round_key = []
    lista = []
    for i in range(len(w)):
        lista.append(xor_hex(w[i], k[0][i]))
    
    round_key.append(lista)
    
    print(round_key)
    
    #Expansio key, continua na expansion key, fazendo os xor restantes.
    for i in range(1,len(k),1):
        lista = []
        for j in range(len(k[i])):
            lista.append(xor_hex(round_key[i-1][j], k[i][j]))
        round_key.append(lista)
    print(round_key)
    return round_key

def aes_encryption(k, plaint):
    print("\nKey:")
    print_list(k)
    print("\n\nPLaintext:")
    print_list(plaint)
    k_round = generate_roundkey(k, 1)
    print(k_round)
    return 0

#Gerar uma chave de 128 bits aleatória
#key = generate_random_key(16)
key = '736174697368636a6973626f72696e67'
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
            x = aes_encryption(key, plaintext)
    else:
        break
