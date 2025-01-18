import random
import random
import hashlib
from operations import esperar_por_enter
import os, base64
import unicodedata
from key_generator import generate_random_key 
from operations import esperar_por_enter, plaintext_tohex, lists_definition, padding_plaintext
from aes_encrypt import aes_encryption

##########################################################################  RSA Core Functions:
def rsa_gerador_primo():
    number_e_primo = False
    k = 128 # Number of test rounds

    # This function implements the Miller-Rabin test to determine whether a number is prime
    def is_prime(n, k):
        r, s = 0, n - 1 
        while s % 2 == 0:   # While s is even
            r += 1          # Increment r
            s //= 2         # Divide s by 2

        for _ in range(k):
            a = random.randint(2, n - 1) # Generate a random number between 2 and n - 1
            x = pow(a, s, n) # x = a^s mod n

            if x == 1 or x == n - 1: # If x is equal to 1 or n - 1,
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        # Return True if number is prime and number passes the Miller-Rabin test
        return True

    while number_e_primo == False:
        get_out = False
        while get_out == False:
            number = random.getrandbits(1024) # Generate a 1024-bit random number
            # Apply a mask to determine value 1 for MSB and LSB (increases the chances of being prime)
            number |= (1 << 1024 - 1) | 1
            # Before we proceed with the code, we check basic things
            if number > 6:  # Valid in some cases
                get_out = True
                #print("It's not a primer - number > 6")
            
            # Test if n is even
            if number >= 1 or number % 2 != 0:
                get_out = True
                #print("It's not a primer - number % 2 != 0")
        #print(number)

        # After generating a 1024-bit number, check if it is prime using Miller-Rabin
        if is_prime(number, k) == True:
            #print("Is a prime number")
            number_e_primo = True

    return number

#--------------------------------------------------------RSA Generate Key:
def rsa_generatekey(p, q):
# Generate an RSA key pair from two 1024-bit prime numbers
    l = []
    def mdc(a, b): # Euclid's Algorithm
            while a != 0: 
                a, b = b % a, a
            return b

    number = p * q
    phi = (p - 1) * (q - 1) # Euler's totient function
    # The public key is a number e such that 1 < e < phi and gcd(e, phi) = 1

#--------------------------------------------------------Code test:
# The code below was abandoned, a 1024-bit number took forever...
# ...to process because of a large RANGE value. We used the POW function.
    # def modInverse(a, m): # Calculates the modular inverse of a mod m (multiplicative inverse)
    # for x in range(1, m):
    # if ((a % m) * (x % m)) % m == 1:
    # return x
 #--------------------------------------------------------Sub-function of RSA_generatekey:           
    def get_random_int(min, max):  # Capture a random number between min and max
        return random.randint(min, max)
            
    temporario_e = 0  # Checks if the found number meets the RSA criteria for e and d
    temp = (get_random_int(1,phi))
    e=0

    while(e==0):
        temporario_e = mdc(temp,phi)
        if temporario_e == 1: 
            e = temp
        else: 
            temp = (get_random_int(1,phi))

    d = pow(e,-1, phi)  # Calculate the multiplicative inverse of e mod phi

    public_key = (number, e)
    private_key = (number, d)
    
    #print("\nPublic keys (e=" + str(e) + ", n=" + str(number) + ")" + "\nPrivate keys (d=" + str(d) + ", n=" + str(number) + ")\n")
    return public_key, private_key
#--------------------------------------------------------Encryption test:

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
    # Assert len(a) == len(b) 
    return bytes([x ^ y for x, y in zip(a, b)])

def bits_to_string(b):
    return ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(b)]*8))

def hash_func(m):
    hashe = hashlib.sha3_256(m)
    return hashe.digest()

# To perform this function, the code available on this site was used:
# https://techoverflow.net/2020/09/27/how-to-perform-bitwise-boolean-operations-on-bytes-in-python3/
def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

# Padding
def mgf1(seed, length):
    hlen = hashlib.sha3_256().digest_size  # Size of SHA-1 hash in bytes
    if length > 2**32 * hlen:
        raise ValueError("mascara muito grande")
    
    t = b""
    counter = 0
    while len(t) < length:
        counter_bytes = counter.to_bytes(4, 'big')
        t += hashlib.sha3_256(seed + counter_bytes).digest()
        counter += 1
    
    return t[:length]

def bytes_to_string(bytes_data):
    # Decode the Base64 bytes to a string
    bits_data = ''.join(format(byte, '08b') for byte in bytes_data)
    base64_data = base64.b64encode(bits_data.encode('utf-8')).decode('utf-8')
    return base64_data

def string_to_bytes(string_data):
    # Encode the Base64 string to bytes
    bits_data = ''.join(format(ord(char), '08b') for char in string_data)
    bytes_data = bytes(int(bits_data[i:i+8], 2) for i in range(0, len(bits_data), 8))
    return bytes_data

##########################################################################  OAEP and Encryption Functions:
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
    '''print("TESTING")
    print('2º',masked_seed)
    print('3º',masked_db)'''

    return em

# Function to remove accents
def remover_acentos(texto):
    return ''.join(c for c in unicodedata.normalize('NFD', texto)
                   if unicodedata.category(c) != 'Mn')

# Rase encrypt
def rsa_encrypt(m, public_key):
    n, e = public_key
    return pow(m,e,n)

def rsa_decrypt(c, private_key):
    n, d = private_key
    return pow(c,d,n)

def oaep_decoding(c, private_key):
    # Decrypt c to m. Decrypt ciphertext
    m = rsa_decrypt(c, private_key)
    #print('2:', m)

    # 1º - IHash = Hash(L)
    ihash = hash_func(b'')

    # 2º - To reverse step 9, split the encoded message EM into the byte 0x00, the maskedSeed (with length hLen) and the maskedDB
    hlen = (len(ihash))
    k = private_key[0].bit_length() // 8
    m = m.to_bytes(k, 'big') # Convert from integer to bytes
    #print('in bytes:', m)
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

    return message.decode('utf-8')

##########################################################################  RSA Main:
def rsa_operations(option):
    if option == '1':  # segunda opção do menu
        if option == '1':
            p = rsa_gerador_primo()
            q = rsa_gerador_primo()
            

            print('='*31)
            print('='*13 + " RSA " + '='*13)
            print('='*31)
            print("\n")
            print('='*5 + ' Key size = 1024 bits ' + '='*5)
            public_key, private_key = rsa_generatekey(p, q)
            print('='*5 + "Generated keys " + '='*5)
            print("Public key: ", public_key)
            print("-"*15)
            print("Private key: ", private_key)
            print("-"*15)

            plain_text = input("Enter the message: ")

            plain_text = remover_acentos(plain_text)

            # OAEP RSA encode
            m = oaep_encoding(plain_text, public_key[0])

            # Find ciphertext
            #print('1:', int.from_bytes(m, byteorder='big'))
            #print('em bytes:', m)
            c = rsa_encrypt(int.from_bytes(m, byteorder='big'),public_key)
            print("\nCiphertext: ",c)
            esperar_por_enter()

            print("\nDECIPHER:")
            esperar_por_enter()

            # Decrypt using oaep decoding function
            texto_decifrado = oaep_decoding(c,private_key)
            print("\nDeciphered text: ", texto_decifrado)
            esperar_por_enter()

            # Generate signature
            print("\nSignature:")
            esperar_por_enter()

            aes_key = generate_random_key(16)
            print(f"\nGenerated key {aes_key}")
            plain_text = plaintext_tohex(plain_text)
            print(f"\nConverted to hexadecimal: {plain_text}")
            plaintext = lists_definition(plain_text)
            plaintext = padding_plaintext(plaintext)
            aes_key = lists_definition(aes_key)
            x = aes_encryption(aes_key, plaintext)
            x = [''.join(lista) for lista in x]
            x = ''.join(x)
            
            # The Signature is: x=AES_k(M), signuture=RSA_KA_s(H(AES_k(M))) and followed by the keys RSA_KA_p and RSA_KA_s
            h_aes_c = sha3_256(x)
            print("\nMessage cypher_text hash: ", h_aes_c)
            # h_aes_c = bytes_to_string(h_aes_c) -> test failed
            signature = rsa_encrypt(int.from_bytes(h_aes_c, byteorder='big'), private_key)
            print("\nRSA_KA_s(H(AES_k(M))) - Signature: ", signature)
            esperar_por_enter()

            # Verification
            #x_encrypt = x
            h_aes_c = sha3_256(x)
            print("Message cypher_text hash:", h_aes_c)
            #texto_decifrado = oaep_decoding(h_aes_c,public_key)
            texto_decifrado = rsa_decrypt(signature,public_key)
            # Wrong Test, ignore
            #texto_decifrado = string_to_bytes(texto_decifrado)
            print("\n\nDeciphered text: ",texto_decifrado)