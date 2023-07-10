import random
#from aes_encrypt import aes_sbox
from operations import xor_hex


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

#Gerar uma chave de 128 bits aleatória
def generate_random_key(length):
    #Gera um número inteiro aleatório com base na quantidade de bits
    key_int = random.getrandbits(length * 8)
    #Converte o número inteiro em bytes e retorna a chave em formato hexadecimal
    key_bytes = key_int.to_bytes(length, byteorder='big')
    return key_bytes.hex()


#Função para gerar a chave da rodada i. (Expansion Key)
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