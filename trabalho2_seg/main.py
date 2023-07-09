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
    plaintext = lists_definition(mensagem)
    plaintext = padding_plaintext(plaintext)
    aes_key = lists_definition(aes_key)
    x = aes_encryption(aes_key, plaintext)
    print(f"\nTexto cifrado: {x}")

    rsa_public_key, rsa_private_key, signuture = rsa_operations('2', x)
    # a Assinatura é: x=AES_k(M), signuture=RSA_KA_s(H(AES_k(M))) e seguido das chaves RSA_KA_p e RSA_KA_s
    sign = (x, signuture, rsa_public_key, rsa_private_key)
    return sign

def verificacao(n, e):
    rsa_aes_encrypt = input("Insira o texto cifrado AES (hexadecimal): ")
    hash_aes_m, aes_encrypt = rsa_operations('3', rsa_aes_encrypt, n, e)
    print(f"\nHash da mensagem: {hash_aes_m}")
    print(f"Texto decifrado em AES: {aes_encrypt}")

if __name__ == '__main__':
    while(1):
        print("\nOpções:\n1 - AES\n2 - RSA\n3 - Assinatura\n4 - Sair")
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
            op_rsa = 0
            while op_rsa != '1' and op_rsa != '2' and op_rsa != '3':
                print("\nOpções:\n1 - Cifração\n2 - Decifração\n3 - Sair")
                op_rsa = input("Escolha a opção: ")
            if (op_rsa == '1'):
                rsa_operations('1')
            elif (op_rsa == '2'):
                n = input("Insira o n da chave privada: ")
                d = input("Insira o d da chave privada: ")
                e = ''
                m = ''
                rsa_operations('4', m, n, e, d)

        elif op == '3':
            op_ass = 0
            while op_ass != '1' and op_ass != '2' and op_ass != '3':
                print("\nOpções:\n1 - Assinar\n2 - Verificar\n3 - Sair")
                op_ass = input("Escolha a opção: ")
            if (op_ass == '1'):
                mensagem = input("Digite a mensagem a ser enviada: ")
                sing = autenticacao(mensagem)
                print("AES_k(M) - Mensagem Criptografada com AES: ", sing[0])
                print("RSA_KA_s(H(AES_k(M))) - Assinatura: ", sing[1])
                print("RSA_KA_p - Chave Pública RSA do emissor: ", sing[2])
                print("-----Mantenha Segredo-----")
                print("RSA_KA_s - Chave Privada RSA do emissor: ", sing[3])

            elif (op_ass == '2'):
                key = input("Insira a chave Púlbica RSA: ")
                verificacao(key)

        elif op == '4':
            break