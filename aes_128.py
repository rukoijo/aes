""" 
Python implementation of the 128-bit key length of the AES cipher. 

The purpose of this implementation 
is for education and not in any way production code. 
"""
# Note! In the lab you should only make modifications to SubBytes, ShiftRows, and AddRoundKey.
# All other functions are working and are verified against testvectors.
# When implementing the functions my advice is to have access to the document. 
# fips197 Announcing the advanced encryption standard (AES) for reference. 

# To test the code you could print the state inside the encryption function. Then you can check against the
# example given in appendix B of the AES document.  


# -------------------------------------------------------------------------------------------------------
# Tables and utility functions. Do not modify this code!
# -------------------------------------------------------------------------------------------------------

# the S-box in AES, the values are verified against the official documentation 
Sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01,	0x67, 0x2b,	0xfe, 0xd7,	0xab, 0x76,
    0xca, 0x82,	0xc9, 0x7d,	0xfa, 0x59,	0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]


def multX(b):
    """Multiplication by x modulo m(x)=x^8 + x^4 + x^3 + x + 1 when b is a byte value. The byte b is 
    considered to be a polynomial of degree at most 7.
    """
    #multiplication by x equals shift 1 step
    b<<=1
    
    #perform modulo calculation
    if b > 255:
        b^=0x11b
    return b


def mult(c,b):
    """The multiplication that is used in MixColumns. The value b is multiplied with the polynomial c.
    Note! The input should be two integers < 255. Internally the funtion multX is used.
    """
    result = 0
    # run over all coefficients of c, if least bit of c is 1 then add b to result
    # after addition multiply b by x and, remove last bit of c 
    while c > 0: 
        if c&1 == 1:
            result ^= b
        b = multX(b)
        c >>= 1
    return result


def print_state(state):
    """Print the 4x4 array in AES. The values are printed in hexadecimal representation.
    This function is useful when we debug our code
    """
    for row in range(4):
        for el in state[row]:
            print(f'{hex(el)[2:]:>02}',end=' ')
        print()


def initiate_input(data):
    """Takes a sequence of 16 integers (or any type theat can be converted to an integer) 
    in the range 0 <= x < 256 and return a 4x4 state-array. 
    
    If the number of elements in the sequence is not 16 and not in the range a ValueError is raised.
    """
    # check length
    if(len(data)) != 16:
        raise ValueError('Input not 16 bytes long')
    
    # generate list of integers of the data
    data_list = [int(el) for el in data]

    # verity that each value is in range 0 <= x <256
    data_err = [el for el in data_list if el < 0 or el > 255]
    if len(data_err) > 0:
        raise ValueError('Input contains values outside valid range')
    
    # write data_list in a 4x4 list
    state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    # copy data
    for row in range(4):
        for col in range(4):
            state[row][col] = data_list[4*col + row]

    return state


def KeyExpansion(key):
    """128-bit key expansion for AES. The input should be a 128-bit key given as a list (or other sequence)
    of 16 byte values. 

    KeyExpansion expands and returns the 128-bit key to the 44 32-bit roundkeys that should be used in AES.
    """

    #initiate the round key to the first 128-bits of the key
    round_keys =  [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for r in range(4):
        for c in range(4):
            round_keys[r][c] = key[4*r + c]
    
    #make room for more round keys
    for i in range(4,44):
        round_keys.append([0, 0, 0, 0])
    
    r_con = 1 # the round constant
    
    # generate round key for round i
    for i in range(4,44):
        # start with previous roundkey
        temp = round_keys[i-1].copy()
        
        # special case when multiple of 4
        if i%4 == 0:
            # rotate list
            temp = temp[1:] + temp[:1]
            # apply S-box
            for j in range(4):
                temp[j] = Sbox[temp[j]]
            # add round constant
            temp[0] ^= r_con
            r_con = multX(r_con)
           
        # add (xor) roundkey 4-steps back
        for j in range(4):
                temp[j] ^= round_keys[i-4][j]
        
        # add temp to roundkeys
        for j in range(4):
            round_keys[i][j] = temp[j]

    return round_keys

# --------------------------------------------------------------------------------------------
# The 4-internal function in AES encryption. 
# --------------------------------------------------------------------------------------------    

def SubBytes(state):
    """Apply the AES S-box to each element in the state. Write the data into a new state"""
    
    # print("------ before SubBytes------")
    # print_state(state)
    
    new_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for row in range(4):
        for column in range(4):
            #extract the byte value from the state and apply the S-box
            new_state[row][column] = Sbox[state[row][column]]
    
    # print("------ after SubBytes------")
    # print_state(new_state)
    
    return new_state



def ShiftRows(state):
    """Shift the rows of the state according the rule for AES ShiftRows. 
    Row i is circular shifted i steps to the left.
    Write the data into a new state"""
    
    # print("------ before ShiftRows------")
    # print_state(state)
    
    new_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for row in range(4):
        for column in range(4):
            # perform the circular shift operation
            new_state[row][column] = state[row][(column+row)%4]
    
    # print("------ after ShiftRows------")
    # print_state(new_state)

    return new_state


def MixColumns(state):
    """Apply the MixColumn operation to the state. The result is returned as new_state.
    MixColumn is based om matrix multiplication with a fixed matrix 
    [2,3,1,1][1,2,3,1][1,1,2,3][3,1,1,2]"""
    new_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    # calculate the answer column wise (use 3 = x + 1)
    for c in range(4):
        new_state[0][c] = multX(state[0][c]) ^ multX(state[1][c]) ^ state[1][c] ^ state[2][c] ^ state[3][c] 
        new_state[1][c] = state[0][c] ^ multX(state[1][c]) ^ multX(state[2][c]) ^ state[2][c] ^ state[3][c]
        new_state[2][c] = state[0][c] ^ state[1][c] ^ multX(state[2][c]) ^ multX(state[3][c]) ^ state[3][c] 
        new_state[3][c] = multX(state[0][c]) ^ state[0][c] ^ state[1][c] ^ state[2][c] ^ multX(state[3][c])
    return new_state


def AddRoundKey(state,rKey,round):
    """ Add the roundkeys for round r to the state. Note! In each round we use 4 separete roundkeys
    rKey[4*r], rKey[4*r+1], rKey[4*r+2], rKey[4*r+2]. Furthermore, the roundkeys are added to the 
    columns of the state"""
    
    # print("------ before AddRoundKey------")
    # print_state(state)

    new_state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for row in range(4):
        for column in range(4):
            # XOR the state with the roundkey
            new_state[row][column] = state[row][column] ^ rKey[4*round + column][row]
    
    # print("------ after AddRoundKey------")
    # print_state(new_state)  
   
    return new_state


# ------------------------------------------------------------------------------------------------------
# The main loop in AES encryption.
# ------------------------------------------------------------------------------------------------------


def aes_encrypt(data, rKey):
    """Encrypt one block of data with AES return the ciphertext as a list with 16 bytes. 
    The rKey is the 44 roundkeys. Use KeyExpansion to generate the round keys before call aes_encrypt."""

    # first generate the state from the data
    state = initiate_input(data)

    # add initial round key before we start
    state = AddRoundKey(state,rKey,0)
    
    # repeat 9 times (10 rounds but final round special)
    for i in range(9):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state,rKey,i+1)

    # final round
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state,rKey,10)

    # generate ciphertext from state
    ciphertext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    for r in range(4):
        for  c in range(4):
            ciphertext[4*c + r] = state[r][c]
    return ciphertext


# -----------------------------------------------------------------------------------------------------
# Test can be used to verify that the implementation of AES is correct. The test values are taken from 
# the AES documentation.
# -----------------------------------------------------------------------------------------------------


def test():
    """Run test vectors"""
    print("Testing AES")

    print("Testing round keys")
    # generate the keys from AES-specification page 27
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    round_keys = KeyExpansion(key)
    
    #verify the roundkeys, from standard document the roundkeys for the first round should be as follows:
    rKey4 = [0xa0, 0xfa, 0xfe, 0x17]
    rKey5 = [0x88, 0x54, 0x2c, 0xb1]
    rKey6 = [0x23, 0xa3, 0x39, 0x39]
    rKey7 = [0x2a, 0x6c, 0x76, 0x05]
    if round_keys[4] == rKey4 and round_keys[5] == rKey5 and round_keys[6] == rKey6 and  round_keys[7] == rKey7:
        print("KeyExpansion ok!")
    else:
        print("Error in KeyExpansion")
    
    # encrypt the test sequence in page 33 (Appendix B) of the AES specification (key as above)
    print("Testing test vector 1")
    data = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
    ciphertext = aes_encrypt(data,round_keys)

    #the ciphertext should be:
    correct_text = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32] 
    if ciphertext == correct_text:
        print("Test vector 1 correct")
    else:
        print("Test vector 1 contains errors")
        print("The calculated ciphertext was:", ciphertext)
        print("Correct value should be: ", correct_text)

    # the second testvector
    data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    correct_text = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]

    round_keys = KeyExpansion(key)
    ciphertext = aes_encrypt(data, round_keys)

    # verify
    if ciphertext == correct_text:
        print("Test vector 2 correct")
    else:
        print("Test vector 2 contains errors")
        print("The calculated ciphertext was:", ciphertext)
        print("Correct value should be: ", correct_text)


# If you run this script it will encrypt two testvectors. 
# Note! In most situations you will use aes_128 as a module in your own applications. 


if __name__ == '__main__':
    """Run the test vectors from the official AES 
    document (FIPS197 Announcing the Advanced Encryption Standard AES)."""   
    test()

