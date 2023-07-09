import random
import random
import secrets
import hashlib
import binascii
import os
import unicodedata

##########################################################################  RSA Core Functions:
def rsa_gerador_primo():
    number_e_primo = False
    k = 128 # número de rodadas de teste

    # Esta função implementa o teste de Miller-Rabin para determinar se um número é primo
    def is_prime(n, k):
        r, s = 0, n - 1 
        while s % 2 == 0: # enquanto s for par
            r += 1 # incrementa r
            s //= 2 # divide s por 2

        for _ in range(k):
            a = random.randint(2, n - 1) # gera um número aleatório entre 2 e n - 1
            x = pow(a, s, n) # x = a^s mod n

            if x == 1 or x == n - 1: # se x for igual a 1 ou n - 1,
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        # return True if number is prime e number passou no teste de Miller-Rabin
        return True

    while number_e_primo == False:
        get_out = False
        while get_out == False:
            number = random.getrandbits(1024) # gera um número aleatório de 1024 bits
            # aplica uma mascara para determinar valor 1 para MSB e LSB (aumenta as chances de ser primo)
            number |= (1 << 1024 - 1) | 1
            # Antes de prosseguirmos com o codigo, verificamos coisas básicas
            if number > 6:  # válida alguns casos
                get_out = True
                # print("Não é primo - number > 6")
            
            # Testa se n é par
            if number >= 1 or number % 2 != 0:
                get_out = True
                # print("Não é primo - number % 2 != 0")
        # print(number)

        # Após gerar um número de 1024 bits, verificar se é primo usamos Miller-Rabin
        if is_prime(number, k) == True:
            # print("É primo")
            number_e_primo = True

    return number

#--------------------------------------------------------RSA Generate Key:
def rsa_generatekey(p, q):
# Gerar um par de chaves RSA de dois números primos de 1024 bits
    l = []
    def mdc(a, b): # Algoritmo de Euclides
            while a != 0: 
                a, b = b % a, a
            return b

    number = p * q
    phi = (p - 1) * (q - 1) # função totiente de Euler
    # A chave pública é um número e e tal que 1 < e < phi e mdc(e, phi) = 1

#--------------------------------------------------------Teste de codigo:
    # Ocodigo abaixo foi abandonado, um numero de 1024 bit demorava uma eternidade...
    #...para processar por conta de um grande valor de RANGE. Usamos a função POW.
    # def modInverse(a, m): # Calcula o inverso modular de a mod m (inverso multiplicativo)
    #     for x in range(1, m):
    #         if ((a % m) * (x % m)) % m == 1:
    #             return x
 #--------------------------------------------------------Sub-function of RSA_generatekey:           
    def get_random_int(min, max):  # captura um número aleatório entre o min e o max
        return random.randint(min, max)
            
    temporario_e = 0  # verifica se o número encontrado obdece os critérios do RSA quanto ao e e d
    temp = (get_random_int(1,phi))
    e=0

    while(e==0):
        temporario_e = mdc(temp,phi)
        if temporario_e == 1: 
            e = temp
        else: 
            temp = (get_random_int(1,phi))

    d = pow(e,-1, phi)  # Calcula o inverso multiplicativo de e mod phi

    public_key = (number, e)
    private_key = (number, d)
    
    # print("\nChaves públicas (e=" + str(e) + ", n=" + str(number) + ")" + "\nChaves privadas (d=" + str(d) + ", n=" + str(number) + ")\n")
    return public_key, private_key
#--------------------------------------------------------Teste de encriptação:

# def encripta_mensagem():
#     def criptografia(m, e, n):
#         c = (m**e) % n
#         return c

#     plain_text = input("Digite a mensagem: \t")
#     print('='*5 + ' Digite as chaves públicas: ' + '='*5)
#     e = int(input("Chave e:   "))
#     n = int(input("Chave n:   ")) 
#     enc = ''.join(chr(criptografia(ord(x), e, n)) for x in plain_text)
#     print('Texto Cifrado: ', enc, '\n')
#     return enc

##########################################################################  Auxiliary Functions:
def sha3_256(message1, message2=None):
    if message2 is not None:
        combined_value = str(message1) + str(message2)
    else:
        combined_value = str(message1)
    sha3_hash = hashlib.sha3_256()
    sha3_hash.update(combined_value.encode('utf-8'))
    return sha3_hash.digest()

def convert_to_bits(n):
    return [int(digit) for digit in bin(n)[2:]]

def pad_bits(bits, length):
    assert len(bits) <= length
    return [0] * (length - len(bits)) + bits

def xor(a, b):
    # assert len(a) == len(b) 
    return bytes([x ^ y for x, y in zip(a, b)])

def bits_to_string(b):
    return ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(b)]*8))

def hash_func(m):
    hashe = hashlib.sha3_256(m)
    return hashe.digest()

# Para relização desta função, foi utilizado o código disponível neste site:
# https://techoverflow.net/2020/09/27/how-to-perform-bitwise-boolean-operations-on-bytes-in-python3/
def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

# padding
def mgf1(seed, length):
    hlen = hashlib.sha3_256().digest_size  # Tamanho do hash SHA-1 em bytes
    if length > 2**32 * hlen:
        raise ValueError("mascara muito grande")
    
    t = b""
    counter = 0
    while len(t) < length:
        counter_bytes = counter.to_bytes(4, 'big')
        t += hashlib.sha3_256(seed + counter_bytes).digest()
        counter += 1
    
    return t[:length]

def oaep_encoding(m, n):

    # 1º: IHash = Hash(L)
    ihash = hash_func(b'')

    # 2º: Generate a padding string PS consisting of k - mLen - 2 * hLen - 2 bytes withe the value 0x00
    hlen = len(ihash)
    mlen = len(m)
    k = n.bit_length() // 8
    ps = (k - mlen - (2 * hlen) - 2)
    ps = b'\x00' * ps

    # 3º: Concatenate ihash, PS, the single byte 0x01, and the message M to form a data block DB
    db = ihash + ps + b'\x01' + m.encode()

    # 4º Generate a random seed of length hLen.
    seed = os.urandom(hlen)

    # 5º Use the mask generating function to generate a
    # mask of the appropriate length for the data block: dbMask = MGF(seed, k - hlen - 1)
    dbmask = mgf1(seed, k - hlen - 1)

    # 6º: Mask the data block with the generated mask: maskedDB = DB xor dbMask
    #masked_db = bytes([a ^ b for a, b in zip(db, dbmask)])
    masked_db = bitwise_xor_bytes(db, dbmask)    

    # 7º: Use the mask generating function to generate a mask of length hLen for the seed:
    # seedMask = MGF(maskedDB, hLen)
    seed_mask = mgf1(masked_db, hlen)

    # 8º: Mask the seed with the generated mask: maskedSeed = seed xor seedMask
    #masked_seed = bytes([a ^ b for a, b in zip(seed, seed_mask)])
    masked_seed = bitwise_xor_bytes(seed, seed_mask) 

    # 9º: The encoded (padded) message is the byte 0x00 concatenated with the maskedSeed and
    # maskedDB: EM = 0x00||maskedSeed||maskedDB
    em = b'\x00' + masked_seed + masked_db  
    '''print("TESTANDOOOOOOOOOOOOOOOOOOOOOO")
    print('2º',masked_seed)
    print('3º',masked_db)'''

    return em

#Função para remover acentos, por exemplo. Entrada: Como você está? -> Saída: Como voce esta?
def remover_acentos(texto):
    return ''.join(c for c in unicodedata.normalize('NFD', texto)
                   if unicodedata.category(c) != 'Mn')

#Rase encrypt
def rsa_encrypt(m, public_key):
    n, e = public_key
    return pow(m,e,n)

def rsa_decrypt(c, private_key):
    n, d = private_key
    return pow(c,d,n)

def oaep_decoding(c, private_key):
    #decifrar c para m. Decifrar texto cifrado
    m = rsa_decrypt(c, private_key)
    #print('2:', m)

    # 1º - IHash = Hash(L)
    ihash = hash_func(b'')

    # 2º - To reverse step 9, split the encoded message EM into the byte 0x00, the maskedSeed (with length hLen) and the maskedDB
    hlen = (len(ihash))
    k = private_key[0].bit_length() // 8
    m = m.to_bytes(k, 'big')#Converter de inteiro para bytes
    #print('em bytes:', m)
    bytes = m[:1]
    masked_seed = m[1 : 1+hlen]
    masked_db = m[1+hlen : ]
    '''print("TESTANDOOOOOOOOOOOOOOOOOOOOOO")
    print('1º',bytes)
    print('2º',masked_seed)
    print('3º',masked_db)'''

    #3º - Generate the seedMask which was used to mask the seed: seedMask = MGF(maskedDB, hLen)
    seed_mask = mgf1(masked_db, hlen)

    #4º - To reverse step 8, recover the seed with the seedMask: seed = maskedSeed xor seedMask
    seed = bitwise_xor_bytes(masked_seed, seed_mask)

    #5º - Generate the dbMask which was used to mask the data block: dbMask = MGF(seed, k - hLen - 1)
    db_mask = mgf1(seed, k - hlen - 1)

    #6º - To reverse step 6, recover the data block DB: DB = maskedDB xor dbMask
    db = bitwise_xor_bytes(masked_db, db_mask)

    message = db[hlen:].lstrip(b'\x00\x01')
    print(message)

    '''i = hlen
    gol = len(db)
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            i += 1

    m = db[i:]'''
    #return m.decode('utf-8')
    #return m
    return message.decode('utf-8')

    
##########################################################################  RSA Cryptography Functions:


##########################################################################  RSA Main:
def rsa_operations():
    p = rsa_gerador_primo()
    q = rsa_gerador_primo()
    

    print('='*31)
    print('='*13 + " RSA " + '='*13)
    print('='*31)
    print("\n")
    print('='*5 + ' Tamanho da chave = 1024 bits ' + '='*5)
    public_key, private_key = rsa_generatekey(p, q)
    print('='*5 + "Chaves geradas " + '='*5)
    print("Chave publica:", public_key)
    print("-"*15)
    print("Chave privada:", private_key)
    print("-"*15)

    plain_text = input("Digite a mensagem:")

    plain_text = remover_acentos(plain_text)

    # OAEP RSA encode
    m = oaep_encoding(plain_text, public_key[0])

    # Encontrar texto cifrado
    #print('1:', int.from_bytes(m, byteorder='big'))
    #print('em bytes:', m)
    c = rsa_encrypt(int.from_bytes(m, byteorder='big'),public_key)
    print("\nTexto cifrado: ",c)

    #Decifrar
    texto_decifrado = oaep_decoding(c,private_key)
    print("\n\nTexto decifrado: ",texto_decifrado)
