import random
import random
import secrets
import hashlib
import binascii

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

def mgf(data, length):
    mgf_data = b''
    counter = 0

    while len(mgf_data) < length:
        if type(data) is str:
            hash_input = data.encode('utf-8') + counter.to_bytes(4, 'big')
        else:
            hash_input = data + counter.to_bytes(4, 'big')
        hash_output = sha3_256(hash_input)
        mgf_data += hash_output
        counter += 1

    return mgf_data[:length]

def generate_random_seed(length):
    seed = secrets.token_bytes(length)
    #print("Semente aleatória:", seed.hex())
    return seed

##########################################################################  OAEP Functions:
def oaep_encode(message, k):
    # Etapa 1: Preenchimento do rótulo
    label = b''
    message = message.encode("utf-8")
    padded_message = message + (b'\x00' * (k - len(message) - len(label) - 1))
    padded_message += b'\x01' + label

    # Etapa 2: Geração do valor aleatório
    seed = generate_random_seed(32)
    seed_bits = int.from_bytes(seed, 'big')
    seed = bin(seed_bits)[2:]  # Remover o prefixo '0b'
    #print("Semente:", type(seed))

    # Etapa 3: MGF (Mask Generation Function)
    mask = mgf(seed, k - len(seed))
    #print("Máscara:", mask.hex())

    # Etapa 4: XOR com o valor aleatório
    masked_message = bytes([padded_message[i] ^ mask[i] for i in range(len(mask))])

    # Etapa 5: MGF (Mask Generation Function)
    masked_message_hex = binascii.hexlify(masked_message).decode('utf-8')  # Converter bytes em hexadecimal
    masked_message_bin = bin(int(masked_message_hex, 16))[2:]  # Converter hexadecimal em binário
    masked_message_str = bits_to_string(masked_message_bin)  # Converter binário em string
    #print("Mensagem mascarada:", masked_message_str)

    masked_seed = mgf(masked_message_str, len(seed))
    #print("Semente mascarada:", masked_seed.hex())

    # Etapa 6: XOR com a semente original
    encoded_message = bytes([masked_message[i] ^ masked_seed[i] for i in range(len(masked_seed))])

    return encoded_message

def oaep_decode(encoded_message, k):
    hlen = len(sha3_256(encoded_message))
    k1 = k - 1 * hlen - 1

    # Etapa 2: Separar as partes do texto codificado (split)
    masked_message, masked_seed = encoded_message[:k1], encoded_message[k1:]

    # Etapa 3: MGF (Mask Generation Function)
    seed = mgf(masked_message, len(masked_seed))

    # Etapa 4: XOR com a semente original
    masked_message = bytes([masked_message[i] ^ seed[i] for i in range(len(seed))])

    # Etapa 5: MGF (Mask Generation Function)
    masked_message_hex = binascii.hexlify(masked_message).decode('utf-8')

    # Etapa 6: Remover preenchimento
    padded_message = '1' + masked_message_hex
    index = padded_message.find('1', 1)
    if index == -1:
        raise ValueError("Preenchimento inválido")
    padded_message = padded_message[index + 1:]
    
    # Etapa 7: Obter a mensagem original
    original_message = bytes.fromhex(padded_message).decode('utf-8')

    return original_message

##########################################################################  RSA Cryptography Functions:


##########################################################################  RSA Main:
if __name__ == '__main__':
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

    print('='*6 + '  Digite o texto em claro  ' + '='*6)
    plain_text = input("Digite a mensagem: \t")
    plain_text = plain_text.replace(" ", "")
    process_text = oaep_encode(plain_text, 32)
    print("oaep encode: ", process_text)
    print("-"*15)
    print("oaep decode: ", oaep_decode(process_text))

