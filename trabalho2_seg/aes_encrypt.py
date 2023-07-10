from operations import esperar_por_enter, xor_hex, print_list
from key_generator import generate_roundkey, aes_sbox

def add_roundkey(plaint, k):
    lenght_plaint = len(plaint)//4
    i_2=0
    for x in range(lenght_plaint):
        for i in range(len(plaint)//lenght_plaint):
            for j in range(len(plaint[i])):
                plaint[i+i_2][j] = xor_hex(plaint[i+i_2][j], k[i][j])
        i_2+=4
    return plaint

#Função que realiza a substituição de bytes
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

#Função que realiza a Shift Rows, movendo os bytes para a esquerda
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

#Função que realiza o embaralhamento de colunas. (MixColumns)
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


#Função que realiza a cifração aes
def aes_encryption(k, plaint):
    print("\nKey:")
    print_list(k)
    print("\nPlaintext:")
    print_list(plaint)
    esperar_por_enter()
    op = 0
    while op != '1' and op != '2':
        print("\n1 - Mostrar resultado direto\n2 - Ver passo a passo")
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

    print("Texto cifrado:",end=" ")
    for linha in plaint:
        for valor in linha:
            print(valor, end='')
    print('\n')
    esperar_por_enter()

    return plaint