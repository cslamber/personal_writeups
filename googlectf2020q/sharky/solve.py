from pwn import *

context.log_level = "debug"

import sha256
import challenge

import struct

#r = process("./challenge.py")
r = remote("sharky.2020.ctfcompetition.com", 1337)


r.recvuntil(b"MSG Digest: ")
digest = bytes.fromhex(r.recvline().strip().decode())
finalsumstate = struct.unpack(">8L", digest)
#print(finalsumstate)

sha = sha256.SHA256()
dubya = sha.compute_w(sha.padding(challenge.MSG))
#print(dubya)
finalstate = tuple((x - y) % 2 ** 32 for x,y in zip(finalsumstate, sha.h))
#print(finalstate)

def uncompression_step(state, kwi):
	tmp2, a, b, c, tmp3, e, f, g = state
	s1 = sha.rotate_right(e, 6) ^ sha.rotate_right(e, 11) ^ sha.rotate_right(e, 25)
	ch = (e & f) ^ (~e & g)
	s0 = sha.rotate_right(a, 2) ^ sha.rotate_right(a, 13) ^ sha.rotate_right(a, 22)
	maj = (a & b) ^ (a & c) ^ (b & c)
	# different
	tmp1 = (tmp2 - s0 - maj) % 2 ** 32
	h = (tmp1 - s1 - ch - kwi) % 2 ** 32
	d = (tmp3 - tmp1) % 2 ** 32
	final = (a, b, c, d, e, f, g, h)
	#assert sha.compression_step(final, kwi, 0) == state
	return final

state = finalstate
# rewind until last 8
for i in range(8, 64)[::-1]:
	state = uncompression_step(state, (dubya[i] + sha.k[i]) % 2 ** 32)
#print(state)

states = [[None for _ in range(8)] for _ in range(9)]
states[0] = list(sha.h)
states[8] = list(state)
for i in range(1, 8)[::-1]:
	states[i][:i] = uncompression_step(states[i+1][:i+1] + [0] * (7 - i), 0)[:i]

for line in states: print(line)

kwi = [None for _ in range(8)]
for i in range(8):
	kwi[i] = (states[i+1][0] - sha.compression_step(states[i], 0, 0)[0]) % 2 ** 32
	states[i+1] = list(sha.compression_step(states[i], kwi[i], 0))

#for line in states: print(line)
print()
print(kwi)

k = [(kw - w) % 2**32 for kw, w in zip(kwi, dubya)]

r.sendline(",".join(hex(x) for x in k))

r.interactive()
