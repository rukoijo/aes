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

names = [["A", "B", "C", "D"],["A","B","C","D"],["A","B","C","D"],["A","B","C","D"]]      
for i in range(4):
    for j in range(4):
        print (names[i][j], end=" ")
    print()
print ("-----------------")
#shift rows 
for i in range(4):
    for j in range(4):
        print (names[i][(j+i)%4], end=" ")
    print()


# names = ["A", "B", "C", "D","E","F","G","H","I","J","K","L","M","N","O","P","Q"]

# for i in range(0,len(names),3):
#     print(names[i], end=" ")



        #     block = aes.xor(block, ciphertext[i-16:i])
        # encrypted_block = aes.aes_encrypt(block, roundKeys)
        # ciphertext.extend(encrypted_block)
  