# new_state = [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]]
# for row in range(4):
#     for column in range(4):
#         # perform the circular shift operation
#         # new_state[row][(column+row)%4]
#         print([row-1][column-1])


# for i in range(4):
#     for j in range(4):
#         print (j, end=" ")
#     print()

# names = [["A", "B", "C", "D"],["A","B","C","D"],["A","B","C","D"],["A","B","C","D"]]      
# for i in range(4):
#     for j in range(4):
#         print (names[i][j], end=" ")
#     print()
# print ("-----------------")
# #shift rows 
# for i in range(4):
#     for j in range(4):
#         print (names[i][(j+i)%4], end=" ")
#     print()


# names = ["A", "B", "C", "D","E","F","G","H","I","J","K","L","M","N","O","P","Q"]

# for i in range(0,len(names),3):
#     print(names[i], end=" ")



        #     block = aes.xor(block, ciphertext[i-16:i])
        # encrypted_block = aes.aes_encrypt(block, roundKeys)
        # ciphertext.extend(encrypted_block)
  

    # """Solves task 4"""
    # print("\nTask4")
    # create a plaintext message, key IV and counter.

    # iv = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    # ctr = iv.copy()
    # data2 = data.copy()

    #encrypt message with cbc and calculate mac
    # cbc_ciphertext = aes_enc.aes_cbc(data, key, iv)
    #mac is the last block of the cbc_ciphertext
    # mac = cbc_ciphertext[-16:]

    #append mac to the data
    # data.extend(mac)
  
    #Encrypt again but now in counter  mode. The output will be the ciphertext that should be transmitted to the receiver
    # ctr_ciphertext = aes_enc.aes_ctr(data, key, ctr)

    #output IV, counter,mac and ciphertext
    # print("IV =>", iv)
    # print("counter =>", ctr)
    # print("ciphertext =>", ctr_ciphertext)
    # print("mac =>", mac)

    # Generate ciphertext + mac
    
    # Encrypt the message twice. Both with countermode and then with cbc mode
    # Use the last block from cbc-mode as a mac and append to the ciphertext from the counter mode

    # Decrypt ciphertext + verify mac
    # Separate mac and ciphertext into two lists.mac is the last block of the cbc_ciphertext
    # Decrypt the data
    # Verify the mac by generating the mac again and verify against the prevoius generated



    # def decrypt_mac(ciphertext,key):
    # iv,ctr,ciphertext = encrypt_mac(data,key)
    # print("ciphertext =>", ciphertext)
    # print("iv =>", iv)
    # print("ctr =>", ctr)

    # #decrypt ciphertext with counter mode
    # plaintext = aes_ctr(ciphertext, key, ctr)
    # # print("plaintext =>", plaintext)

    # #remove mac from plaintext
    # mac = plaintext[-16:]
    # # print("mac =>", mac)
    # data = plaintext[:-16]
    # # print("plaintext =>", data)

    # #decrypt data with cbc mode
    # plaintext = aes_cbc(data, key, iv)
    # # print("plaintext =>", plaintext)

    # #remove mac from plaintext
    # mac2 = plaintext[-16:]
    # # print("mac =>", mac2)
    # data2 = plaintext[:-16]
    # # print("plaintext =>", data2)

    # #compare macs
    # if mac == mac2:
    #     print("macs are equal")
    # else:
    #     print("macs are not equal")

    #remove padding
    # data = unpad(data2)
    # # print("plaintext =>", data)
    # return data


ama = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14]
print(ama[-5:])
print(ama[:-5])