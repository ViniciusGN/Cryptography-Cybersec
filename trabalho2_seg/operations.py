#Xor entre 2 valores.
def xor_hex(byte1, byte2):
    int1 = int(byte1, 16)
    int2 = int(byte2, 16)
    result = int1^int2
    result = format(result, '02x')
    return result

#faz um print da lista no formato de uma matrix 4x4. Podendo ser mais de uma matrix
def print_list(lista):
    for elements in zip(*lista):
        j=0
        for element in elements:
            if j==4:
                j=0
                print(end='   ')
            j+=1
            print(element, end=' ')
        print()

def esperar_por_enter():
    input("Pressione Enter para continuar...")

#Converte para hexadecimal
def plaintext_tohex(plaint):
    #plaint_hex = ''.join(hex(ord(c))[2:] for c in plaint)
    '''plaint_bytes = plaint.encode('utf-8')
    plaint_hex = plaint_bytes.hex()'''
    plaint = plaint.encode('iso-8859-1').hex()
    return plaint

#Converter hexadecimal para caracter
def plaintext_tocharacter(plaint):
    caracteres = ''.join(chr(int(plaint[i:i+2], 16)) for i in range(0, len(plaint), 2) if plaint[i:i+2] > "0f")
    return caracteres

#Padroniza a string em formato de listas, dentro daa lista há outras listas de tamanho 4
def lists_definition(text):
    text_list = []
    text_matriz = []
    for i in range(0, len(text), 2):
        text_list.append(text[i:i+2])
    for i in range(0, len(text_list), 4):
        text_matriz.append(text_list[i:i+4])
    return text_matriz

#Realiza o padding do plaintext, método utilizado é o PKCS#7
def padding_plaintext(plaint):
    lenght = sum(len(i) for i in plaint)
    byte_padding = hex(16 - (lenght%16)).replace("0x","")
    missing_lists = 4 - (len(plaint)%4)

    '''flag = 0
    if missing_lists == 4:
        for i in plaint:
            if len(i) == 4:
                flag += 1
        if flag/4 == 0:
            return plaint'''
    
    for lista in plaint:
        if len(lista) < 4:
            lista.extend(['0'+byte_padding] * (4 - len(lista)))

    if missing_lists == 4:
        return plaint
    
    for i in range(missing_lists):
        lista = []
        lista.extend(['0'+byte_padding] * 4)
        plaint.append(lista)

    return plaint 