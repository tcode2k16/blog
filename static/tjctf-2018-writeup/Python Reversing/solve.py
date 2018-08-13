# flag: tjctf{pYth0n_1s_tr1v14l}

from itertools import *
import numpy as np

# flag = 'tjctf{'

# np.random.seed(12345)
# arr = np.array([ord(c) for c in flag])
# other = np.random.randint(1,5,(len(flag)))
# arr = np.multiply(arr,other)

# b = [x for x in arr]
# lmao = [ord(x) for x in ''.join(['ligma_sugma_sugondese_'*5])]

# print lmao

# c = [b[i]^lmao[i] for i,j in enumerate(b)]
# print(list(bin(x)[2:].zfill(8) for x in c))
# print(''.join(bin(x)[2:].zfill(8) for x in c))

# original_output was 100110000 10111101 10100001 10000101 00000111 10101001 100100011101111110100011111010101010000000110000011101101110000101111101010111011100101000011011010110010100001100010001010101001100001110110100110011101




def decode(message):
  lmao = [ord(x) for x in ''.join(['ligma_sugma_sugondese_'*5])]
  for l in combinations([x for x in range(19, 25)], 0):
    counter = 19
    index = 0
    arr = [304, 189, 161, 133, 7, 169, 291, 382, 143, 341, 1, 131, 366, 23, 427, 370, 134, 428, 161]
    isGood = True
    while counter < 25:
      if counter in l:
        if message[index:index+9][0] == '0':
          isGood = False
        arr.append(int(message[index:index+9], 2))
        index += 9
      else:
        arr.append(int(message[index:index+8], 2))
        index += 8
      counter += 1
    # if not isGood:
    #   break
    # print l
    print(arr)
    arr = [j^lmao[i] for i , j in enumerate(arr)]
    # print(arr)
    np.random.seed(12345)
    arr = np.array(arr)
    other = np.random.randint(1,5,(len(arr)))
    arr = np.divide(arr, other).tolist()
    print ''.join([chr(x) for x in arr])

  # splitCipher = lambda A, n: [A[i:i+n] for i in range(0, len(A), n)]
  # chars = splitCipher(message, 8)
  # print chars

decode('100010001010101001100001110110100110011101')