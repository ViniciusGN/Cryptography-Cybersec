from operations import esperar_por_enter, plaintext_tohex, lists_definition, padding_plaintext
from aes_encrypt import aes_encryption
from aes_decrypt import aes_decryption
from key_generator import generate_random_key 
from rsa import rsa_operations

def autenticacao(mensagem):
    aes_key = generate_random_key(16)
    print(f"\nGenerated key {aes_key}")
    mensagem = plaintext_tohex(mensagem)
    print(f"Converted to hexadecimal: {mensagem}")
    plaintext = lists_definition(mensagem)
    plaintext = padding_plaintext(plaintext)
    aes_key = lists_definition(aes_key)
    x = aes_encryption(aes_key, plaintext)
    x = [''.join(lista) for lista in x]
    x = ''.join(x)
    #print(f"\nCiphertext: {x}")

    rsa_public_key, rsa_private_key, signuture = rsa_operations('2', x)
    # The Signature is: x=AES_k(M), signuture=RSA_KA_s(H(AES_k(M))) and followed by the keys RSA_KA_p and RSA_KA_s
    sign = (x, signuture, rsa_public_key, rsa_private_key)
    return sign

def verificacao(n, e):
    rsa_aes_encrypt = input("Enter AES ciphertext (hexadecimal): ")
    hash_aes_m, aes_encrypt = rsa_operations('3', rsa_aes_encrypt, n, e)
    print(f"\nMessage Hash: {hash_aes_m}")
    print(f"AES decrypted text: {aes_encrypt}")

if __name__ == '__main__':
    while(1):
        print("\Options:\n1 - AES\n2 - RSA\n3 - Quit")
        op = input("Choose option: ")
        if (op == '1'):
            op_aes = 0
            while op_aes != '1' and op_aes != '2' and op_aes != '3':
                print("\Options:\n1 - Encryption\n2 - Decipherment\n3 - Quit")
                op_aes = input("Choose option: ")
            if (op_aes == '1'):
                # Generate random key
                key = generate_random_key(16)
                print(f"\nGenerated key {key}")
                plaintext = input("\nInsert text (16 ASCII characters): ")

                # Convert plaintext to hexadecimal
                plaintext = plaintext_tohex(plaintext)
                print(f"Converted to hexadecimal: {plaintext}")
                esperar_por_enter()

                # Creates lists according to plaintext
                plaintext = lists_definition(plaintext)
                plaintext = padding_plaintext(plaintext)
                key = lists_definition(key)
                x = aes_encryption(key, plaintext)

            elif (op_aes == '2'):
                text = input("Enter ciphertext (hexadecimal): ")
                key = input("Enter the key that was used to encrypt the text (hexadecimal): ")
                #text = plaintext_tohex(text)
                #key = plaintext_tohex(key)
                text = lists_definition(text)
                key = lists_definition(key)
                x = aes_decryption(key, text)

        elif op == '2':
            rsa_operations('1')

        elif op == '3':
            break