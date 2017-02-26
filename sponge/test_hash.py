#!/usr/bin/env python
import sys
from Crypto.Cipher import AES



# looks like it works on 10 byte blocks of plaintext and produces 20 bytes of output

# copied for debugging and modification
class Hasher:
  # uses AES-128 as it's base crypto primative with a static key of 16 bytes all null
  def __init__(self):
    self.aes = AES.new('\x00'*16)

   # initialize state to a 16 byte block of all null
  def reset(self):
    self.state = '\x00'*16

  # hashing a block is done by doing AES((block || \0 x 6) ^ state)
  def ingest(self, block):
    """Ingest a block of 10 characters """
    block += '\x00'*6
    state = ""
    for i in range(16):
      state += chr(ord(self.state[i]) ^ ord(block[i]))
    self.state = self.aes.encrypt(state)

  # finalization is done by padding the last block (or creating a second block of a full pad)
  def final_ingest(self, block):
    """Call this for the final ingestion.

    Calling this with a 0 length block is the same as calling it one round
    earlier with a 10 length block.
    """
    if len(block) == 10:
      self.ingest(block)
      print("debug pad_block: " + ('\x80' + '\x00'*8 + '\x01').encode('hex'))
      self.ingest('\x80' + '\x00'*8 + '\x01')
    elif len(block) == 9:
      print("debug pad_block: " + (block + '\x81').encode('hex'))
      self.ingest(block + '\x81')
    else:
      print("debug pad_block: " + (block + '\x80' + '\x00'*(8-len(block)) + '\x01').encode('hex'))
      self.ingest(block + '\x80' + '\x00'*(8-len(block)) + '\x01')

  # sqeezing is done returning the first 10 bytes of the state while setting the next state to be it's own encryption
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
    self.final_ingest(s[blocks*10:])

    return self.squeeze() + self.squeeze()


nom = Hasher()

print nom.hash(sys.argv[1]).encode('hex')


