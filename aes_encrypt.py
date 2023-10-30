""" Python implementation of some modes of operations to encrypt data with 
the AES algorithm.
The module aes_128 provides the actual implementation of the algorithms.  
"""
import aes_128 as aes

# In the lab you should modify aes_ecb, aes_cbc and aes_ctr such that they work according to the specification of the modes
# Do not modify pad and unpad


# In order to be able to encrypt data of any length we need to be able to pad data such that the length is a multiple of 16 bytes.
# We can then use pad and unpad to perform this padding.

def pad(data):
    """Pad add extra bytes to the end of a sequence of bytes to make it a multiple of 16 bytes.
    The padding calculates how many bytes that should be added. Call this number n. Then append n bytes with the value n. 
    Note! If the data length is a multiple of 16 then 16 bytes will be padded anyway. This is to ensure that unpad will 
    always produce correct result."""

    #calculate number of bytes to pad
    numbers_pad = 16 - (len(data)%16)

    plaintext = data.copy()
    # pad number_pad times
    for i in range(numbers_pad):
        plaintext.append(numbers_pad)
    return plaintext

def unpad(plaintext):
    """Removes the padded bytes. This function assumes that the plaintext has been padded according to the rules for pad"""

    # find the number of bytes to remove (written in last byte of plaintext)
    number_remove = plaintext[-1]
    data = plaintext[:-number_remove]
    return data

# The different modes

def aes_ecb(data, key):
    """The Electronic Code Book mode. """

    # start by padding the data since we need 16-byte blocks
    plaintext = pad(data)

    #initiate aes by calculating the roundkeys
    

    # encrypt each block of data and store in ciphertext
    ciphertext = []
    
    return ciphertext

def aes_cbc(data, key, iv):
    """The cbc mode"""
        
    # start by padding the data since we need 16-byte blocks
    plaintext = pad(data)

    #initiate roundkey
    roundKeys = aes.KeyExpansion(key)

    # encrypt each block
    # before yoy encrypt a block of plaintext you should add (xor)
    # previous ciphertext block to the block of plaintext
    # for the first block xor with the IV

    ciphertext = []
    
    return ciphertext


def aes_ctr(data, key, ctr):
    """The counter mode of AES. This is a simplified version were we take the initial value of the counter as input and
    in each iteration we increment the last byte of ctr."""

    # initiate the aes by generating roundkeys
    roundkeys = aes.KeyExpansion(key)

    # generate a keystream that should be used to encrypt the data
    # to generate the keystream do the following
    # start by encrypting the value of the counter ctr
    # this will produce the first part of the keystream
    # then add 1 to the counter and encrypt the counter again to produce more keystream bytes
    # repeat until you have enough keystream
    keystream = []

    # encrypt each byte of the data with keystream
    ciphertext = data.copy()

    return ciphertext


if __name__ == '__main__':
    """If the module is run as a script print a message on how to use the module"""
    print("aes_encrypt is a module that implements some mode of operations of AES.")
    print("Electronic code book: aes_ecb")
    print("Cipher Block Chaining: aes_cbc")
    print("Counter mode: aes_ctr")
    print("\nTo use the module you import it into your script with:")
    print("import aes_encrypt as aes_enc")
