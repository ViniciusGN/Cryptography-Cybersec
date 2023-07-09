from operations import esperar_por_enter, plaintext_tohex, lists_definition, padding_plaintext
from aes_encrypt import aes_encryption
from aes_decrypt import aes_decryption
from key_generator import generate_random_key 
from rsa import rsa_operations

def autenticacao(mensagem):
    aes_key = generate_random_key(16)
    print(f"\nChave gerada {aes_key}")
    mensagem = plaintext_tohex(mensagem)
    print(f"Convertido em hexadecimal: {mensagem}")
    plaintext = lists_definition(plaintext)
    plaintext = padding_plaintext(plaintext)
    key = lists_definition(key)
    x = aes_encryption(key, plaintext)
    print(f"\nTexto cifrado: {x}")

    rsa_public_key, rsa_private_key, signuture = rsa_operations(2, x)
    # a Assinatura é: x=AES_k(M), signuture=RSA_KA_s(H(AES_k(M))) e seguido das chaves RSA_KA_p e RSA_KA_s
    sign = (x, signuture, rsa_public_key, rsa_private_key)
    return sign

def verificacao(rsa_public_key):
    rsa_aes_encrypt = input("Insira o texto cifrado AES (hexadecimal): ")
    hash_aes_m, aes_encrypt = rsa_operations(3, rsa_aes_encrypt, rsa_public_key)
    print(f"\nHash da mensagem: {hash_aes_m}")
    print(f"Texto decifrado em AES: {aes_encrypt}")

if __name__ == '__main__':
    while(1):
        print("\nOpções:\n1 - AES\n2 - RSA\n3 - Sair")
        op = input("Escolha a opção: ")
        if (op == '1'):
            op_aes = 0
            while op_aes != '1' and op_aes != '2' and op_aes != '3':
                print("\nOpções:\n1 - Cifração\n2 - Decifração\n3 - Sair")
                op_aes = input("Escolha a opção: ")
            if (op_aes == '1'):
                #Gera chave aleatória
                key = generate_random_key(16)
                print(f"\nChave gerada {key}")
                plaintext = input("\nInsira um texto (16 ASCII characters): ")

                #Converte o plaintext para hexadecimal
                plaintext = plaintext_tohex(plaintext)
                print(f"Convertido em hexadecimal: {plaintext}")
                esperar_por_enter()

                #Cria listas de acordo com o plaintext
                plaintext = lists_definition(plaintext)
                plaintext = padding_plaintext(plaintext)
                key = lists_definition(key)
                x = aes_encryption(key, plaintext)
            elif (op_aes == '2'):
                text = input("Insira um texto cifrado (hexadecimal): ")
                key = input("Insira a chave que foi usada para cifrar o texto (hexadecimal): ")
                #text = plaintext_tohex(text)
                #key = plaintext_tohex(key)
                text = lists_definition(text)
                key = lists_definition(key)
                x = aes_decryption(key, text)
        elif op == '2':
            rsa_operations(1)
        elif op == '3':
            break