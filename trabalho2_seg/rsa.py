from random import randrange
import random

def rsa_gerador_primo():
    print("Flag 1")
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
    def inverso_modular(a, m): # Algoritmo de Euclides estendido
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        print('Não ha inverso modular para o bloco.\n')
        return None

    number = p * q
    phi = (p - 1) * (q - 1) # função totiente de Euler
    # A chave pública é um número e e tal que 1 < e < phi e mdc(e, phi) = 1

    for x in range(2, phi): 
        if mdc(phi, x) == 1 and inverso_modular(x, phi) != None: #  MDC(φ(n), e) = 1
            l.append(x)
    for x in l:
        if x == inverso_modular(x,phi):
            l.remove(x)
    # A lista l contém todos os possíveis valores para e (valores co-primos para chave pública)
    e = random.choice(l)

    d = inverso_modular(e,phi) # calculo da chave privada d*e = 1 mod(φ(n))
    return print("\nChaves públicas (e=" + str(e) + ", n=" + str(number) + ")" + "\nChaves privadas (d=" + str(d) + ", n=" + str(number) + ")\n")

def rsa_operations():
    p = rsa_gerador_primo()
    q = rsa_gerador_primo()
    # q = rsa_gerador_primo()
    print(p)
    print("------------------")
    print(q)
    print("------------------")
    print(rsa_generatekey(p, q))