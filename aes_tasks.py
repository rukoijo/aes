"""This script can be used to solve the tasks for lab 1 in the course wireless network security. Together with this script you have two modules
aes_128 that should implement the AES algorithm and aes_encrypt that should implement three different modes.

You must first correct the implementation of AES in aes_128 before you implement the modes. When both AES and the modes are working you have some 
tasks to solve. The solution to these tasks should be done in the functions below."""

import aes_encrypt as aes_enc
import aes_128 as aes

def task1():
    """"Run the test of AES. 
    Do not proceed with the rest of the lab until this task is successfull."""
    print("Task 1")
    aes.test()

def task2():
    """Test the different modes of encryption."""
    print("\nTask 2")
    # the first test is based on the standard vectors from the documentation. Thus part of the ciphertext can be found in the documentation.

    data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    correct_text = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
    iv = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    ctr = data.copy()
    data2 = iv.copy()

    # test ecb mode
    ciphertext = aes_enc.aes_ecb(data, key)
    print(ciphertext)

    # test cbc mode
    ciphertext = aes_enc.aes_cbc(data, key, iv)
    print(ciphertext)

    #test ctr mode
    ciphertext = aes_enc.aes_ctr(data, key, ctr)
    print(ciphertext)

    # when have finished the basic test add code to solve task 2.

def task3():
    """"put your solution to task 3 here"""
    print("\nTask 3")

def task4():
    """Solves task 4"""
    print("\nTask4")
    # create a plaintext message, key IV and counter.

    # Generate ciphertext + mac
    # Encrypt the message twice. Both with countermode and then with cbc mode
    # Use the last block from cbc-mode as a mac and append to the ciphertext from the counter mode

    # Decrypt ciphertext + verify mac
    # Separate mac and ciphertext into two lists
    # Decrypt the data
    # Verify the mac by generating the mac again and verify against the prevoius generated

   


if __name__ == '__main__':
    """Run the tasks that solves the lab. You can add comments in order to only run the task you are solving right now."""   
    task1()
    task2()
    task3()
    task4()
