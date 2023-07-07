from sympy import isprime

num = 171618563911515493102096641926062684150981008784922037555259335406254337633363868181022899140863414896111419867899306584745638377251814154093425771565457054819063206551473089298805372240340302831311168585577640556852236395756649585236305580138640782975631637100109615861488526357622428812497394397268063753159

if isprime(num):
    print(f"{num} é um número primo.")
else:
    print(f"{num} não é um número primo.")

# s = 0
#         r = number - 1
#         while r & 1 == 0:
#             s += 1
#             r //= 2
            
#         # executa k testes
#         for _ in range(k):
#             print(_)
#             a = randrange(2, number - 1)
#             x = pow(a, r, number)
#             if x != 1 and x != number - 1:
#                 j = 1
#                 while j < s and x != number - 1:
#                     x = pow(x, 2, number)
#                     if x == 1:
#                         number_e_primo = False
#                         # print("Não é primo - 1")
#                     j += 1
                
#                     if x != number - 1:
#                         number_e_primo = False
#                         # print("Não é primo - 2")
#         number_e_primo = True