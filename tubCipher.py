"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Python 3 implementation of the TUBCipher as described in its original paper.
The purpose of this implementation is to gather data in order to complete a
security analysis of the cipher.

Author: Yannick Beaupré, 04/2022 (MM/YYYY)

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import math
import sys

"""
bitsToNum, hexStreamToBits and num2bits are all helper functions 
which facilate the conversion from one data type to another.
"""

def bitsToNum(bits, size):
	result = 0
	for i in range(size):
		index = (size - 1) - i
		if(bits[index] == 1):
			result += (2 ** i)
	
	return result

def hexStreamToBits(num, size):
	result = []
	for i in range(int(size/4)):
		value = int(num[i], 16)
		
		bit4 = value % 2
		value = math.floor(value/2)
		
		bit3 = value % 2
		value = math.floor(value/2)
		
		bit2 = value % 2
		value = math.floor(value/2)
		
		bit1 = value % 2
		value = math.floor(value/2)
		
		result.append(bit1)
		result.append(bit2)
		result.append(bit3)
		result.append(bit4)
		
	return result
    
def num2bits(num, bitlength):
	bits = []
	for i in range(bitlength):
		bits.append(num & 1)
		num >>= 1
	
	result = []
	for i in range(bitlength): 
		result.append(bits[bitlength - i - 1])
	
	return result
	
def enc(plaintext, long_key, showWork):
	"""
	Encrypts a 27-bit plaintext with a 2560-bit key
	"""
	
	#BitString to array of bits
	text = []
	for i in range(27):
		text.append(int(plaintext[i]))
		
	key = hexStreamToBits(long_key, 2560)
	
	#Repeat for 56 rounds
	for roundNum in range(56):
		if(showWork):
			print(roundNum+1)
		
		#Prepare both sub keys needed
		XORKeyStart = 45*roundNum
		permKeyStart = (45*roundNum)+27
		
		#key xor
		for i in range(27):
			text[i] = text[i] ^ key[XORKeyStart + i]
	
		if(showWork):
			print(bitsToNum(text, 27))
	
		#Fixed permutation
		state = [None] * 27
		for i in range(26):
			state[(3 * i) % 26] = text[i]
		state[26] = text[26]
		
		text = state
		
		if(showWork):
			print(bitsToNum(text, 27))
		
		
		for i in range(9):
			c0 = 3*i 
			c1 = 3*i + 1 
			c2 = 3*i + 2
			a0 = (2*i) + permKeyStart
			a1 = (2*i + 1) + permKeyStart
			
			#Keyed permutation
			if( (key[a0] == 0) and (key[a1] == 0)):
				#Do nothing (python request there be something here)
				c0 = c0
			elif((key[a0] == 0) and (key[a1] == 1)):
				temp = text[c0]
				text[c0] = text[c1]
				text[c1] = temp
			elif((key[a0] == 1) and (key[a1] == 0)):
				temp = text[c1]
				text[c1] = text[c2]
				text[c2] = temp
			else:
				temp = text[c0]
				text[c0] = text[c2]
				text[c2] = temp
		
			#Fixed substitution
			W = 0
			if (text[c0] == 1):
				W += 4
			if (text[c1] == 1):
				W += 2
			if (text[c2] == 1):
				W += 1

			if(W == 2):
				text[c0] = 0
				text[c1] = 1
				text[c2] = 1
			elif(W == 3):
				text[c0] = 1
				text[c1] = 1
				text[c2] = 0
			elif(W == 4):
				text[c0] = 1
				text[c1] = 1
				text[c2] = 1
			elif(W == 5):
				text[c0] = 1
				text[c1] = 0
				text[c2] = 0
			elif(W == 6):
				text[c0] = 1
				text[c1] = 0
				text[c2] = 1
			elif(W == 7):
				text[c0] = 0
				text[c1] = 1
				text[c2] = 0
				
		if(showWork):
			print(bitsToNum(text, 27))
			print()
	
	return bitsToNum(text, 27)

def dec(ciphertext, long_key, showWork):
	"""
	Decrypts a 27-bit ciphertext with a 2560 bit key
	"""

	text = num2bits(ciphertext, 27)
	key = hexStreamToBits(long_key, 2560)
	
	#Repeat for 56 rounds
	for count in range(56):
		roundNum = 55 - count
		if(showWork):
			print(roundNum+1)
		
		#Prepare both sub keys needed
		XORKeyStart = 45*roundNum
		permKeyStart = (45*roundNum)+27
		
		for i in range(9):
			c0 = 3*i 
			c1 = 3*i + 1 
			c2 = 3*i + 2
			a0 = (2*i) + permKeyStart
			a1 = (2*i + 1) + permKeyStart
			
			#Fixed substitution
			W = 0
			if (text[c0] == 1):
				W += 4
			if (text[c1] == 1):
				W += 2
			if (text[c2] == 1):
				W += 1

			if(W == 2):
				text[c0] = 1
				text[c1] = 1
				text[c2] = 1
			elif(W == 3):
				text[c0] = 0
				text[c1] = 1
				text[c2] = 0
			elif(W == 4):
				text[c0] = 1
				text[c1] = 0
				text[c2] = 1
			elif(W == 5):
				text[c0] = 1
				text[c1] = 1
				text[c2] = 0
			elif(W == 6):
				text[c0] = 0
				text[c1] = 1
				text[c2] = 1
			elif(W == 7):
				text[c0] = 1
				text[c1] = 0
				text[c2] = 0
			
			#Keyed permutation
			if( (key[a0] == 0) and (key[a1] == 0)):
				#Do nothing (python request there be something here)
				c0 = c0
			elif((key[a0] == 0) and (key[a1] == 1)):
				temp = text[c0]
				text[c0] = text[c1]
				text[c1] = temp
			elif((key[a0] == 1) and (key[a1] == 0)):
				temp = text[c1]
				text[c1] = text[c2]
				text[c2] = temp
			else:
				temp = text[c0]
				text[c0] = text[c2]
				text[c2] = temp
		
		if(showWork):
			print(bitsToNum(text, 27))
			
		#Fixed permutation
		state = [None] * 27
		for i in range(26):
			state[i] = text[(3 * i) % 26]
		state[26] = text[26]
		
		text = state
		
		if(showWork):
			print(bitsToNum(text, 27))
	
		#key xor
		for i in range(27):
			text[i] = text[i] ^ key[XORKeyStart + i]
	
		if(showWork):
			print(bitsToNum(text, 27))
			print()
	
	return bitsToNum(text, 27)
	
#Handles command line arguments for troubleshooting purposes
showWork = False
if(len(sys.argv) > 1):
	if (sys.argv[1] == "t"):
		showWork = True
		
