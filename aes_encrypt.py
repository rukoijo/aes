""" Python implementation of some modes of operations to encrypt data with 
the AES algorithm.
The module aes_128 provides the actual implementation of the algorithms.  
"""
import aes_128 as aes
import os

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
    roundKeys = aes.KeyExpansion(key)

    # encrypt each block of data and store in ciphertext
    ciphertext = []
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        encrypted_block = aes.aes_encrypt(block, roundKeys)
        ciphertext.extend(encrypted_block)
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
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        if i == 0:
            block_xor = [a ^ b for a, b in zip (block, iv)]
        else:
            block_xor = [a ^ b for a, b in zip (block, ciphertext[i-16:i])]
        encrypted_block = aes.aes_encrypt(block_xor, roundKeys)
        ciphertext.extend(encrypted_block)
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
    for i in range(0, len(data), 16):
        block = aes.aes_encrypt(ctr, roundkeys)
        keystream.extend(block)
        ctr[-1] += 1
    
    # print("-- keystream -- ")
    # print(len(data))
    # print(keystream)
    # print("---------- ")

    # encrypt each byte of the data with keystream
    # to encrypt a byte xor the byte with the keystream byte of the same index
    # the result is the ciphertext byte

    ciphertext = []
    # ciphertext = data.copy()
    for i in range(len(data)):
        ciphertext.append(data[i] ^ keystream[i])
    
    return ciphertext

def encrypt_mac(data,key):
    """"input parameters: data and key. output parameters: IV, counter, ciphertext, mac is calculated from cbc mode and appended to the data. encryption
    is done in counter mode."""
    #randomly generate IV and counter
    iv = list(os.urandom(16))
    ctr = list(os.urandom(16))

    #encrypt message with cbc and extract mac
    cbc_ciphertext = aes_cbc(data, key, iv)
    #mac is the last block of the cbc_ciphertext
    mac = cbc_ciphertext[-16:]

    #append mac to data to get mac+data=plaintext
    data = data.copy()
    data.extend(mac)
    plaintext = data.copy()

    #Encrypt again but now in counter  mode. The output will be the ciphertext that should be transmitted to the receiver
    ctr_ciphertext = aes_ctr(plaintext, key, ctr.copy())

    # output IV, Counter and Ciphertext.
    # print("key =>", key)
    print("IV =>", iv)
    print("counter =>", ctr)
    # print("mac(cbc) =>", mac)
    # print("plaintext(mac+data) =>", plaintext)
    print("ciphertext =>", ctr_ciphertext)

    return iv,ctr,ctr_ciphertext

def decrypt_mac(iv,ctr,ciphertext,key):
    """decrypts ciphertext and verifies mac. input parameters: ciphertext, key, iv, ctr. output parameters: plaintext, mac(original), mac_2(calculated), mac_status."""
    #decrypt ciphertext with counter mode because it was encrypted with counter mode
    # print("ctr = ",ctr)
    decrypted_data = aes_ctr(ciphertext, key, ctr)
    # print("key =>", key)
    # print("plaintext(mac+data) =>", decrypted_data)

    #extract mac from decrypted_data
    mac = decrypted_data[-16:]
    # print("mac =>", mac)

    #extract plaintext from decrypted_data
    plaintext = decrypted_data[:-16]
    # print("plaintext =>", plaintext)

    #Calculate MAC using the extracted plaintext, key, and IV
    mac_2 = aes_cbc(plaintext, key, iv)[-16:]
    print("calculated mac =>", mac_2)

    #Check if the calculated MAC matches the extracted MAC
    if mac == mac_2:
        print("mac valid =>", True)
    else:
        print("mac valid =>", False)

    return plaintext

if __name__ == '__main__':
    """If the module is run as a script print a message on how to use the module"""
    print("aes_encrypt is a module that implements some mode of operations of AES.")
    print("Electronic code book: aes_ecb")
    print("Cipher Block Chaining: aes_cbc")
    print("Counter mode: aes_ctr")
    print("\nTo use the module you import it into your script with:")
    print("import aes_encrypt as aes_enc")
