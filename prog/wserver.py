#server code block          

import socket


# S-Box for encoding the data
sBox = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7,]

# Inverse S-Box for decoding the message 
sBoxI = [0xA,0x5,0x9,0xB,0x1,0x7,0x8,0xf,0x6,0x0,0x2,0x3,0xC,0x4,0xD,0xE,]

def init(key): # Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
    
    pre_round_key, round1_key, round2_key = key_expansion(key)

    
def sub_word(word):
    return (sBox[(word >> 4)] << 4) + sBox[word & 0x0F]
    

        #Substitute word Block
        # Take each nibble in the word and substitute another nibble for it using the Sbox table
    
def rot_word(word):
    
        #Rotate word block
        # Swapping the two nibbles in the word since eqv to rotate here
    return ((word & 0x0F) << 4) + ((word & 0xF0) >> 4)


def gf_mult(a, b):
    """Galois field multiplication of a and b in GF(2^4) / x^4 + x + 1
        :param a: First number
        :param b: Second number
        :returns: Multiplication of both under GF(2^4)
        """
        # Initialise
    product = 0

        # Mask the unwanted bits
    a = a & 0x0F
    b = b & 0x0F

        # While both multiplicands are non-zero
    while a and b:

            # If LSB of b is 1
        if b & 1:

                # Add current a to product
            product = product ^ a

            # Update a to a * 2
        a = a << 1

            # If a overflows beyond 4th bit
            
        if a & (1 << 4):

                # XOR with irreducible polynomial with high term eliminated
            a = a ^ 0b10011

            # Update b to b // 2
        b = b >> 1

    return product

def int_to_state(n): #Convert a 2-byte integer into a 4-element vector (state matrix) and it returns the state corresponding to the integer value 
        
        return [n >> 12 & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF, n & 0xF]

    
def state_to_int(m): #Convert a 4-element vector (state matrix) into 2-byte integer and it returns the integer corresponding to the state
        
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

def add_round_key(s1, s2): #Add round keys in GF(2^4) ,(s1 -> First number),(s2 -> Second number) and it returns the Addition of both under GF(2^4)
        
    return [i ^ j for i, j in zip(s1, s2)]

def sub_nibbles(sbox, state): #block for Nibble substitution(sbox for Substitution box to use for transformation) ( State to perform sub nibbles transformation on , return the Resultant state )
        
    return [sbox[nibble] for nibble in state]

def shift_rows(state): # Shift rows and inverse shift rows of state matrix (same) , State to perform shift rows transformation and returns Resultant state)
        
    return [state[0], state[1], state[3], state[2]]

def mix_columns(state):#Mix columns transformation on state matrix , State to perform mix columns transformation  ,Resultant state
        
    return [
            state[0] ^ gf_mult(4, state[2]),
            state[1] ^ gf_mult(4, state[3]),
            state[2] ^ gf_mult(4, state[0]),
            state[3] ^ gf_mult(4, state[1]),
        ]

def inverse_mix_columns(state):#Inverse mix columns transformation on state matrix, State to perform inverse mix columns transformation and Resultant the state )
        
    return [
            gf_mult(9, state[0]) ^ gf_mult(2, state[2]),
            gf_mult(9, state[1]) ^ gf_mult(2, state[3]),
            gf_mult(9, state[2]) ^ gf_mult(2, state[0]),
            gf_mult(9, state[3]) ^ gf_mult(2, state[1]),
        ]

def encrypt(plaintext,key):#Encrypt plaintext with given key
    state = add_round_key(int_to_state(key),int_to_state(plaintext))
   # print("After preround transformation: ")
   # print(bin(state_to_int(state)))
    
    state = sub_nibbles(sBox, state)
   # print("After Round 1 Substitute nibbles:")
   # print(bin(state_to_int(state)))
    
    state = shift_rows(state)
   # print("After Round 1 Shift rows:")
   # print(bin(state_to_int(state)))
    
    state = mix_columns(state)
   # print("After Round 1 Mix columns:")
   # print(bin(state_to_int(state)))

    #state = mix_columns(shift_rows(sub_nibbles(sBox, state)))

    state = add_round_key(int_to_state(key), state)
   # print("After Round 1 Add round key:")
   # print(bin(state_to_int(state)))
    
    state = sub_nibbles(sBox, state)
   # print("After Round 2 Substitute nibbles:")
   # print(bin(state_to_int(state)))
    
    state = shift_rows(state)
   # print("After Round 2 Shift rows:")
   # print(bin(state_to_int(state)))

    state =add_round_key(int_to_state(key), state)
   # print("After Round 2 Add round key:")
   # print(bin(state_to_int(state)))
    

    return state_to_int(state)

def decrypt(ciphertext,key):
    state = add_round_key(int_to_state(key), int_to_state(ciphertext))
   # print("After Pre-round transformation:")
   # print(bin(state_to_int(state)))
    
    state = shift_rows(state)
   # print("After Round 1 InvShift rows:")
   # print(bin(state_to_int(state)))

    state = sub_nibbles(sBoxI, state)
   # print("After Round 1 InvSubstitute nibbles:")
   # print(bin(state_to_int(state)))
    
    state = add_round_key(int_to_state(key), state)
   # print("After Round 1 InvAdd round key:")
   # print(bin(state_to_int(state)))

    state = inverse_mix_columns(state)
   # print("After Round 1 InvMix columns:")
   # print(bin(state_to_int(state)))
    
    state = shift_rows(state)
   # print("After Round 2 InvShift rows:")
   # print(bin(state_to_int(state)))

    state = sub_nibbles(sBoxI, state)
   # print("After Round 2 InvSubstitute nibbles:")
   # print(bin(state_to_int(state)))

    state = add_round_key(int_to_state(key), state)
   # print("After Round 2 Add round key:")
   # print(bin(state_to_int(state)))

    return state_to_int(state)


plaintext = 0b1010100110111001
key = 0b1110101110100101
ciphertext = encrypt(plaintext,key)
print("The input plaintext is :" + bin(plaintext) )
print("The key for decryption is " + bin(key))
print("The cipher text is " + bin(ciphertext))
#print(plaintext)
#print("The input plaintext is :" + PT )

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket is being created and using ipv4 and tcp connection )
s.bind(('localhost', 9999))
s.listen(5)
while True:
    clt, adr=s.accept()
    print(f"Connection to {adr} established")
    clt.send(bytes(str(ciphertext),'utf-8'))
    break
s.close
