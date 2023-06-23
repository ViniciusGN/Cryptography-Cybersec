import random
import os

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

    if missing_lists == 4:
        return plaint
    
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

def print2_list(matriz1, matriz2):
    matriz1_transposta = list(map(list, zip(*matriz1)))
    matriz2_transposta = list(map(list, zip(*matriz2)))
    
    for col1, col2 in zip(matriz1_transposta, matriz2_transposta):
        # Concatena as colunas com um espaço entre elas
        col_concatenada = " ".join(str(x) for x in col1) + "    |    " + " ".join(str(x) for x in col2)
        print(col_concatenada)

def xor_hex(byte1, byte2):
    int1 = int(byte1, 16)
    int2 = int(byte2, 16)
    result = int1^int2
    result = format(result, '02x')
    return result

#Função que retorna a S-box para a função subBytes() e generate_roundkey()
def aes_sbox():
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
    
    return s_box


def generate_roundkey(k, r):
    

    #Recebe a S-box
    s_box = aes_sbox()

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
    #print(w)
    
    #Expansion key: Primeiro faz o xor entre w e k[0] 
    round_key = []
    lista = []
    for i in range(len(w)):
        lista.append(xor_hex(w[i], k[0][i]))
    
    round_key.append(lista)
    
    #print(round_key)
    
    #Expansio key, continua na expansion key, fazendo os xor restantes.
    for i in range(1,len(k),1):
        lista = []
        for j in range(len(k[i])):
            lista.append(xor_hex(round_key[i-1][j], k[i][j]))
        round_key.append(lista)
    #print(round_key)
    return round_key

def add_roundkey(plaint, k):
    lenght_plaint = len(plaint)//4
    i_2=0
    for x in range(lenght_plaint):
        for i in range(len(plaint)//lenght_plaint):
            for j in range(len(plaint[i])):
                plaint[i+i_2][j] = xor_hex(plaint[i+i_2][j], k[i][j])
        i_2+=4
    return plaint

def subBytes(plaintext):
    #Recebe a S-box
    s_box = aes_sbox()

    lenght_plaint = len(plaintext)//4
    i_2=0
    for x in range(lenght_plaint):
        for i in range(len(plaintext)//lenght_plaint):
            for j in range(len(plaintext[i])):
                byte = plaintext[i+i_2][j]
                lin = int(byte[0],16)
                col = int(byte[1],16)
                plaintext[i+i_2][j] = s_box[lin][col]
        i_2+=4
    return plaintext

def shiftRows(plaintext):
    lenght_plaint = len(plaintext)//4
    i=0
    for x in range(lenght_plaint):
        first_element = plaintext[0+i][1]
        plaintext[0+i][1] = plaintext[1+i][1]
        plaintext[1+i][1] = plaintext[2+i][1]
        plaintext[2+i][1] = plaintext[3+i][1]
        plaintext[3+i][1] = first_element

        element = plaintext[0+i][2]
        plaintext[0+i][2] = plaintext[2+i][2]
        plaintext[2+i][2] = element
        element = plaintext[1+i][2]
        plaintext[1+i][2] = plaintext[3+i][2]
        plaintext[3+i][2] = element

        firstelement = plaintext[0+i][3]
        plaintext[0+i][3] = plaintext[3+i][3]
        plaintext[3+i][3] = plaintext[2+i][3]
        element = plaintext[1+i][3]
        plaintext[1+i][3] = firstelement
        plaintext[2+i][3] = element

        i+=4   

    return plaintext


def mixColumns(plaintext):

    multiplication_by_2 = [
        ['00','02','04','06','08','0a','0c','0e','10','12','14','16','18','1a','1c','1e'],
        ['20','22','24','26','28','2a','2c','2e','30','32','34','36','38','3a','3c','3e'],
        ['40','42','44','46','48','4a','4c','4e','50','52','54','56','58','5a','5c','5e'],
        ['60','62','64','66','68','6a','6c','6e','70','72','74','76','78','7a','7c','7e'],
        ['80','82','84','86','88','8a','8c','8e','90','92','94','96','98','9a','9c','9e'],
        ['a0','a2','a4','a6','a8','aa','ac','ae','b0','b2','b4','b6','b8','ba','bc','be'],
        ['c0','c2','c4','c6','c8','ca','cc','ce','d0','d2','d4','d6','d8','da','dc','de'],
        ['e0','e2','e4','e6','e8','ea','ec','ee','f0','f2','f4','f6','f8','fa','fc','fe'],
        ['1b','19','1f','1d','13','11','17','15','0b','09','0f','0d','03','01','07','05'],
        ['3b','39','3f','3d','33','31','37','35','2b','29','2f','2d','23','21','27','25'],
        ['5b','59','5f','5d','53','51','57','55','4b','49','4f','4d','43','41','47','45'],
        ['7b','79','7f','7d','73','71','77','75','6b','69','6f','6d','63','61','67','65'],
        ['9b','99','9f','9d','93','91','97','95','8b','89','8f','8d','83','81','87','85'],
        ['bb','b9','bf','bd','b3','b1','b7','b5','ab','a9','af','ad','a3','a1','a7','a5'],
        ['db','d9','df','dd','d3','d1','d7','d5','cb','c9','cf','cd','c3','c1','c7','c5'],
        ['fb','f9','ff','fd','f3','f1','f7','f5','eb','e9','ef','ed','e3','e1','e7','e5']
    ]
    multiplication_by_3 = [
        ['00', '03', '06', '05', '0c', '0f', '0a', '09', '18', '1b', '1e', '1d', '14', '17', '12', '11'], 
        ['30', '33', '36', '35', '3c', '3f', '3a', '39', '28', '2b', '2e', '2d', '24', '27', '22', '21'], 
        ['60', '63', '66', '65', '6c', '6f', '6a', '69', '78', '7b', '7e', '7d', '74', '77', '72', '71'], 
        ['50', '53', '56', '55', '5c', '5f', '5a', '59', '48', '4b', '4e', '4d', '44', '47', '42', '41'], 
        ['c0', 'c3', 'c6', 'c5', 'cc', 'cf', 'ca', 'c9', 'd8', 'db', 'de', 'dd', 'd4', 'd7', 'd2', 'd1'], 
        ['f0', 'f3', 'f6', 'f5', 'fc', 'ff', 'fa', 'f9', 'e8', 'eb', 'ee', 'ed', 'e4', 'e7', 'e2', 'e1'], 
        ['a0', 'a3', 'a6', 'a5', 'ac', 'af', 'aa', 'a9', 'b8', 'bb', 'be', 'bd', 'b4', 'b7', 'b2', 'b1'], 
        ['90', '93', '96', '95', '9c', '9f', '9a', '99', '88', '8b', '8e', '8d', '84', '87', '82', '81'], 
        ['9b', '98', '9d', '9e', '97', '94', '91', '92', '83', '80', '85', '86', '8f', '8c', '89', '8a'], 
        ['ab', 'a8', 'ad', 'ae', 'a7', 'a4', 'a1', 'a2', 'b3', 'b0', 'b5', 'b6', 'bf', 'bc', 'b9', 'ba'], 
        ['fb', 'f8', 'fd', 'fe', 'f7', 'f4', 'f1', 'f2', 'e3', 'e0', 'e5', 'e6', 'ef', 'ec', 'e9', 'ea'], 
        ['cb', 'c8', 'cd', 'ce', 'c7', 'c4', 'c1', 'c2', 'd3', 'd0', 'd5', 'd6', 'df', 'dc', 'd9', 'da'], 
        ['5b', '58', '5d', '5e', '57', '54', '51', '52', '43', '40', '45', '46', '4f', '4c', '49', '4a'], 
        ['6b', '68', '6d', '6e', '67', '64', '61', '62', '73', '70', '75', '76', '7f', '7c', '79', '7a'], 
        ['3b', '38', '3d', '3e', '37', '34', '31', '32', '23', '20', '25', '26', '2f', '2c', '29', '2a'], 
        ['0b', '08', '0d', '0e', '07', '04', '01', '02', '13', '10', '15', '16', '1f', '1c', '19', '1a']
    ]

    lenght_plaint = len(plaintext)//4
    i_2=0
    new_plaintext = []
    for x in range(lenght_plaint):
        for i in range(4):
            lista = []
            byte = plaintext[i+i_2][0]
            byte2 = plaintext[i+i_2][1]
            valor1 = xor_hex(multiplication_by_2[int(byte[0],16)][int(byte[1],16)], multiplication_by_3[int(byte2[0],16)][int(byte2[1],16)])
            valor2 = xor_hex(plaintext[i+i_2][2],plaintext[i+i_2][3])
            lista.append(xor_hex(valor1,valor2))

            byte = plaintext[i+i_2][1]
            byte2 = plaintext[i+i_2][2]
            valor1 = xor_hex(plaintext[i+i_2][0], multiplication_by_2[int(byte[0],16)][int(byte[1],16)])
            valor2 = xor_hex(multiplication_by_3[int(byte2[0],16)][int(byte2[1],16)],plaintext[i+i_2][3])
            lista.append(xor_hex(valor1,valor2))

            byte = plaintext[i+i_2][2]
            byte2 = plaintext[i+i_2][3]
            valor1 = xor_hex(plaintext[i+i_2][0], plaintext[i+i_2][1])
            valor2 = xor_hex(multiplication_by_2[int(byte[0],16)][int(byte[1],16)], multiplication_by_3[int(byte2[0],16)][int(byte2[1],16)])
            lista.append(xor_hex(valor1,valor2))

            byte = plaintext[i+i_2][0]
            byte2 = plaintext[i+i_2][3]
            valor1 = xor_hex(multiplication_by_3[int(byte[0],16)][int(byte[1],16)], plaintext[i+i_2][1])
            valor2 = xor_hex(plaintext[i+i_2][2],multiplication_by_2[int(byte2[0],16)][int(byte2[1],16)])
            lista.append(xor_hex(valor1,valor2))
            new_plaintext.append(lista)
        i_2+=4

    return new_plaintext

def esperar_por_enter():
    input("Pressione Enter para continuar...")


def aes_encryption(k, plaint):
    print("\nKey:")
    print_list(k)
    print("\nPlaintext:")
    print_list(plaint)
    esperar_por_enter()
    print("1 - Mostrar resultado direto")
    print("2 - Ver passo a passo")
    op = input("Selecione a opção: ")
    
    if op == '2':
        print('\nAdd Round Key, Round 0')
        plaint = add_roundkey(plaint, k)
        print("State Matrix:")
        print_list(plaint)
        esperar_por_enter()
        for i in range (1,11,1):

            print(f"\nSubstitution Bytes, Round {i}")
            plaint = subBytes(plaint)
            print_list(plaint)
            esperar_por_enter()

            print(f"\nShift Row, Round {i}")
            plaint = shiftRows(plaint)
            print_list(plaint)
            esperar_por_enter()

            #Função mixColumns() não deve ser executada na rodada 10
            if i != 10:
                print(f"\nMix Column, Round {i}")
                plaint = mixColumns(plaint)
                print_list(plaint)
                esperar_por_enter()
            
            k = generate_roundkey(k, i)
            print(f"\nKey Round {i}")
            print_list(k)
            esperar_por_enter()

            plaint = add_roundkey(plaint, k)
            print(f"\nAdd Round Key, Round {i}")
            print_list(plaint)
            esperar_por_enter()

            print("\nState Matrix:")
            print_list(plaint)
            esperar_por_enter()

    else:
        plaint = add_roundkey(plaint, k)

        for i in range (1,11,1):
            plaint = subBytes(plaint)
            plaint = shiftRows(plaint)
            if i!=10:
                plaint = mixColumns(plaint)
            k = generate_roundkey(k, i)
            plaint = add_roundkey(plaint, k)

        print("\nState Matrix:")
        print_list(plaint)

    return 0

#Gerar uma chave de 128 bits aleatória
#key = generate_random_key(16)
key = '5468617473206d79204b756e67204675'
print(key)

while(1):
    #key = generate_random_key(16)
    key = '5468617473206d79204b756e67204675'
    print("\nOpções:\n1 - AES")
    op = input("Escolha a opção: ")
    if (op == '1'):
        print("Opções:\n1 - Cifração\n2 - Decifração")
        op_aes = input("Escolha a opção: ")
        if (op_aes == '1'):
            plaintext = input("Insira um texto: ")
            #os.system('cls')#Limpa a tela do console
            plaintext = plaintext_tohex(plaintext)
            plaintext = '54776f204f6e65204e696e652054776f'
            #plaintext =  '876e46a6f24ce78c4d904ad897ecc395'
            plaintext = lists_definition(plaintext)
            plaintext = padding_plaintext(plaintext)
            key = lists_definition(key)
            #print(plaintext)
            #print(key)
            '''plaintext = [
                ['87','6e','46','a6'],
                ['f2','4c','e7','8c'],
                ['4d','90','4a','d8'],
                ['97','ec','c3','95']
                ]'''
            x = aes_encryption(key, plaintext)
    else:
        break
