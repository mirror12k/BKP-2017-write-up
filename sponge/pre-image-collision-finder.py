#!/usr/bin/env python

import sys
from Crypto.Cipher import AES
from hash import Hasher
import itertools



class ModifiedHasher:
	def __init__(self):
		self.aes = AES.new('\x00'*16)
	def debug(self, info, stuff):
		print "[debug]", info, ':', stuff
	def debug_hex(self, info, stuff):
		print "[debug]", info, ':', stuff.encode('hex')

	def reset(self):
		self.state = '\x00'*16

	def ingest(self, block):
		"""Ingest a block of 10 characters """
		block += '\x00'*6
		state = ""
		for i in range(16):
			state += chr(ord(self.state[i]) ^ ord(block[i]))
		self.state = self.aes.encrypt(state)

	def final_ingest(self, block):
		"""Call this for the final ingestion.

		Calling this with a 0 length block is the same as calling it one round
		earlier with a 10 length block.
		"""
		if len(block) == 10:
			self.ingest(block)
			self.ingest('\x80' + '\x00'*8 + '\x01')
		elif len(block) == 9:
			self.ingest(block + '\x81')
		else:
			self.ingest(block + '\x80' + '\x00'*(8-len(block)) + '\x01')

	def squeeze(self):
		"""Output a block of hash information"""
		result = self.state[:10]
		self.state = self.aes.encrypt(self.state)
		return result

	def hash(self, s):
		"""Hash an input of any length of bytes.  Return a 160-bit digest."""
		self.reset()
		blocks = len(s) // 10
		for i in range(blocks):
			self.ingest(s[10*i:10*(i+1)])
			self.debug_hex('ingest state', self.state)
		self.final_ingest(s[blocks*10:])
		self.debug_hex('final state', self.state)

		return self.state

class PreImageCollisionFinder(object):
	def __init__(self, vector_table_size=1000000):
		self.aes = AES.new('\x00'*16)
		self.vector_table_size = vector_table_size
	def debug(self, info, stuff):
		print "[debug]", info, ':', stuff
	def debug_hex(self, info, stuff):
		print "[debug]", info, ':', stuff.encode('hex')


	def find_collision(self, target_output_state):
		self.debug_hex('target_output_state', target_output_state)
		first_block_vectors = self.generate_vectors()
		self.debug('generated first_block_vectors', len(first_block_vectors))

		first_block, third_block = self.collide_against_vectors(first_block_vectors, target_output_state)

		self.debug_hex('first_block', first_block)
		self.debug_hex('third_block', third_block)

		second_block = self.fix_second_block(first_block, third_block, target_output_state)
		self.debug_hex('first_block', first_block)
		self.debug_hex('second_block', second_block)
		self.debug_hex('third_block', third_block)

		return first_block + second_block + third_block

	def generate_vectors(self):
		first_block_vectors = {}
		i = 0
		for test_block in itertools.imap(''.join, itertools.product([ chr(i) for i in range(256) ], repeat=6)):
			block = test_block + '\x00' * 4
			full_block = block + '\x00' * 6
			vector = self.aes.encrypt(full_block)
			vector = vector[-6:]
			first_block_vectors[vector] = block
			if i % 1000000 == 0:
				self.debug('first_block_vectors i', i)
			if i >= self.vector_table_size:
				break
			else:
				i += 1
		return first_block_vectors

	def collide_against_vectors(self, first_block_vectors, output_state):
		intermediate_state_3 = self.aes.decrypt(output_state)
		pad_block =  '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01' + '\x00' * 6
		intermediate_state_3 = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(intermediate_state_3, pad_block))
		self.debug_hex('intermediate_state_3', intermediate_state_3)
		intermediate_state_2 = self.aes.decrypt(intermediate_state_3)

		# need to xor with third_block and decrypt to produce vectors for intermediate_state_1
		i = 0
		for test_block in itertools.imap(''.join, itertools.product([ chr(i) for i in range(256) ], repeat=6)):
			block = test_block + '\x00' * 4
			full_block = block + '\x00' * 6
			temp_state_2 = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(intermediate_state_2, full_block))
			vector = self.aes.decrypt(temp_state_2)
			if first_block_vectors.get(vector[-6:]) is not None:
				self.debug_hex('intermediate_state_2', temp_state_2)
				self.debug_hex('tail', vector[-6:])
				self.debug_hex('vector', vector)
				return first_block_vectors.get(vector[-6:]), block
			if i % 1000000 == 0:
				self.debug('collide i', i)
			i += 1
		return None



	def fix_second_block(self, first_block, third_block, output_state):
		intermediate_state_3 = self.aes.decrypt(output_state)
		pad_block =  '\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01' + '\x00' * 6
		intermediate_state_3 = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(intermediate_state_3, pad_block))
		self.debug_hex('intermediate_state_3', intermediate_state_3)
		intermediate_state_2 = self.aes.decrypt(intermediate_state_3)
		full_third_block = third_block + '\x00' * 6
		intermediate_state_2 = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(intermediate_state_2, full_third_block))
		self.debug_hex('intermediate_state_2', intermediate_state_2)
		intermediate_state_1_reverse = self.aes.decrypt(intermediate_state_2)
		self.debug_hex('intermediate_state_1_reverse', intermediate_state_1_reverse)

		full_first_block = first_block + '\x00' * 6
		intermediate_state_1_forward = self.aes.encrypt(full_first_block)
		self.debug_hex('intermediate_state_1_forward', intermediate_state_1_forward)

		diff = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(intermediate_state_1_forward, intermediate_state_1_reverse))

		self.debug_hex('diff', diff)

		return diff[:10]





if __name__ == '__main__':
	input_text = sys.argv[1]
	target_output_state = ModifiedHasher().hash(input_text)
	finder = PreImageCollisionFinder(vector_table_size=2000000)
	text = finder.find_collision(target_output_state)
	print text.encode('hex')
	verify = ModifiedHasher().hash(text)
	print 'verify: ', verify.encode('hex'), 'vs', target_output_state.encode('hex')
