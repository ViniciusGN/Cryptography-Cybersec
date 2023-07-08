from random import randrange
import random

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

    # Ocodigo abaixo foi abandonado, um numero de 1024 bit demorava uma eternidade...
    #...para processar por conta de um grande valor de RANGE. Usamos a função POW.
    # def modInverse(a, m): # Calcula o inverso modular de a mod m (inverso multiplicativo)
    #     for x in range(1, m):
    #         if ((a % m) * (x % m)) % m == 1:
    #             return x
            
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
    
    print("\nChaves públicas (e=" + str(e) + ", n=" + str(number) + ")" + "\nChaves privadas (d=" + str(d) + ", n=" + str(number) + ")\n")
    return public_key, private_key

def encripta_mensagem():
    def criptografia(m, e, n):
        c = (m**e) % n
        return c

    plain_text = input("Digite a mensagem: \t")
    print('='*5 + ' Digite as chaves públicas: ' + '='*5)
    e = int(input("Chave e:   "))
    n = int(input("Chave n:   ")) 
    enc = ''.join(chr(criptografia(ord(x), e, n)) for x in plain_text)
    print('Texto Cifrado: ', enc, '\n')
    return enc

if __name__ == '__main__':
    p = rsa_gerador_primo()
    q = rsa_gerador_primo()
    # q = rsa_gerador_primo()
    print(p)
    print("------------------")
    print(q)
    print("------------------")

    public_key, private_key = rsa_generatekey(p, q)
    cypher_text = encripta_mensagem()
    print(cypher_text)
