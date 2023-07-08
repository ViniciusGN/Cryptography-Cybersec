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

def oaep_deteste(EM, label = b'') -> bytes:
        """ EME-OAEP-Decode(EM, P)
        Options: 
            1. Hash - hash function (hLen denotes the length in octets of the hash function output)
            2. MGF - mask generation function
        Input: 
            1. EM - encoded message, an octet string of length at least 2hLen + 1 (emLen denotes the length in
            octets of EM)
            2. P - Encoding parameters, an octet string
        Output:
            1. M - recovered message, an octet string of length at most emLen - 1 - 2hLen

        Errors:
            1. Decoding error
        """
        # steps:
        # 1. If the length of P is greater than the input limitation then output ‘‘decoding error’’ and stop.
        # SHA1: 2^61 - 1
        if len(label) > (pow(2, 61) - 1):
            raise ValueError("Decoding error, parameter too large")
        # 2. If emLen < 2hLen + 1, output ‘‘decoding error’’ and stop.
        emLen = len(EM) 
        lHash = sha3_256(label)
        hLen = len(lHash)
        
        # if emLen < ((2*hLen) + 1):
        #     raise ValueError("Decoding error, parameter too large")
        # 3. Let maskedSeed be the first hLen octets of EM and let maskedDB be the remaining emLen-hLen octets.
        maskedSeed = EM[0:hLen]
        maskedDB = EM[hLen+1:-1]
        # 4.  Let seedMask = MGF(maskedDB, hLen).
        seedMask =  mgf(maskedDB, hLen)
        # 5. Let seed = maskedSeed xor seedMask.
        seed = xor(maskedSeed,seedMask) 
        # 6. Let dbMask = MGF(seed , emLen - hLen)
        dbMask = mgf(seed, emLen - hLen)
        # 7. Let DB = maskedDB xor dbMask.
        DB = xor(maskedDB, dbMask)
        # 8. Let pHash = Hash(P), an octet string of length hLen.
        index = DB.find(b'\x01') + 1
        if lHash not in DB:
            raise ValueError("Hash not in DB")

        # 9. Separate DB into an octet string pHash’ || PS || 01 || M
        # 10. return m
        return DB[index:]

def oaep_enteste(M:str, emLen, label= b"") -> bytes:
    """
    OAEP encoding operation:

    Inputs:
        - M: message to be encoded, an octet string of length at most (emLen - 1 - 2hLen)
        (mLen denotes the length in octets of the message)  
        - P: Encoding Parameters, an octet string
        -emLen: intended length in octets of the encoded message, at least 2hLen + 1
    Options: 
        - Hash hash function (hLen denotes the length in octets of the hash function output)
        - MGF mask generation function
    Output:
        - EM: encoded message, an octet string of length emLen
    Exceptions:
         -Message too long; Parameter string too long
    """
    # 1. If the length of P is greater than the input limitation for the hash function
    # (2^61 - 1 octets for SHA-1) then output ‘‘parameter string too long’’ and stop.

    # 2. let pHash = Hash(P), an octet string of length hLen.
    M = M.encode('utf-8')
    lHash = sha3_256(label)
    hLen = len(lHash)
    mLen = len(M)    
    # 4. Generate an octet string PS consisting of (emLen − mLen − 2hLen − 1) zero octets. 
    # The length of PS may be 0.

    # PADDING:
    zero_octet = b'\x00'
    PS = zero_octet * (emLen - mLen - 2*hLen - 2)
    # 5. Concatenate lHash, PS, the message M, and other padding to form a data block DB as
    #  DB = lHash + PS + 01 + M.
    DB = lHash + PS + b'\x01' + M
    # 6. Generate a random octet string seed of length hLen.
    seed = generate_random_seed(hLen)

    # 7. Let dbMask = MGF(seed , emLen − hLen)
    dbMask = mgf(seed, emLen - hLen)
    #8.  Let maskedDB = DB xor dbMask.
    maskedDB = xor(DB, dbMask)
    # 9. Let seedMask = MGF(maskedDB, hLen).
    seedMask = mgf(maskedDB, hLen)
    # 10. Let maskedSeed = seed xor seedMask.
    maskedSeed = xor(seed, seedMask)
    # 11. Let EM = maskedSeed + maskedDB.
    EM = maskedSeed + maskedDB

    # 12. Output EM.

    return EM