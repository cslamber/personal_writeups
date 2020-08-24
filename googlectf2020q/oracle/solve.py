from pwn import *
import aegis
import challenge
import aes_basics

import base64
import struct
import itertools

import differentials

context.log_level = "debug"

#r = process("./challenge.py")
r = remote("oracle2.2020.ctfcompetition.com", 1337)

def read():
	while True:
		line = r.recvline().strip()
		if line.startswith(b"DEBUG: "):
			continue
		try:
			return base64.b64decode(line)
		except:
			pass

def write(data):
	r.sendline(base64.b64encode(data))

_xor = aes_basics._xor

def _and(a,b):
	return bytes([x&y for x,y in zip(a,b)])

# aad is always useless in this chal
AAD = bytes()

# bins for aes round
bins = [[0, 5, 10, 15], [4, 9, 14, 3], [8, 13, 2, 7], [12, 1, 6, 11]]

# PHASE 1 --- standard differentials against AEGIS128L
#
# we only get 7 encryptions, so we have to leak out a lot of the
# initial state each time---there's 128 bytes in the state.  at
# the start we have no information about the state since the key's
# randomness pretty much goes everywhere.
#
# there's no point in using aad since it's the same as encrypting
# it just doesn't give us output.  in general, we can attempt to
# inject a differential and get differences from 1 and 5 each run.
# this means over 6 runs we need to read out 64 bytes, which would
# be impossible---BUT we can get around this by only getting out
# 48 bytes and backcalculating for the last 16.  then, we can
# get those 48 by doing standard deterministic differentials on the
# aes round function.


iv = read()

write(bytes(32) * 10) # write 10 zero words
write(AAD) # aad is useless
zeroct, _ = read(), read() # we don't care about the tag


S = [None for _ in range(8)]
for i in range(3): # for S1/S5, S2/S6, S3/S7
	round = [[None for _ in range(16)] for _ in range(2)]
	known = [[None for _ in range(4)] for _ in range(2)]
	for diffround, (diff, _) in enumerate(differentials.p1dd):
		# for the plaintext, we want to go out until we start diffing the relevant
		# block. for s1/s5 that's nothing
		pt = bytes()
		for _ in range(i):
			pt += bytes(32)
		# now write the differential, but twice so that we hit both 0 and 4
		pt += diff * 2
		# get 2 blocks from now in order to actually read the diff
		pt += bytes(32) * 2
		write(pt)
		write(AAD) # aad is useless
		ct, _ = read(), read() # tag is useless
		ct = aes_basics._xor(ct, zeroct)
		# read into the relevant block (the last) and get diffed
		diffed = ct[(i+2)*32:(i+3)*32]
		fh, sh = diffed[:16], diffed[16:]
		fh = struct.unpack(">IIII", fh)
		sh = struct.unpack(">IIII", sh)
		for k in range(4):
			if diffround == 0:
				known[0][k] = differentials.p1solve(fh[k], 1)
				known[1][k] = differentials.p1solve(sh[k], 1)
			else:
				proven = [
					known[0][k] & differentials.p1solve(fh[k], 2),
					known[1][k] & differentials.p1solve(sh[k], 2),
				]
				assert len(proven[0]) == 1
				assert len(proven[1]) == 1
				proven = list(map(min, proven))
				for l in range(4):
					round[0][bins[k][l]] = proven[0][l]
					round[1][bins[k][l]] = proven[1][l]

	round[0] = bytes(round[0])
	round[1] = bytes(round[1])
	if i == 0:
		S[0] = round[0]
		S[4] = round[1]
	elif i == 1:
		# first read the difference from the last one
		round[0] = _xor(round[0], S[0])
		round[1] = _xor(round[1], S[4])
		# then, we want to move this back one
		S[7] = differentials.unaes(round[0])
		S[3] = differentials.unaes(round[1])
	elif i == 2:
		# more complicated: we currently have S[0] and S[4] after 2 iterations,
		# so we need to wind it back,
		# first get it after 1 iteration and xor
		round[0] = _xor(aes_basics.aes_enc(S[7], S[0]), round[0])
		round[1] = _xor(aes_basics.aes_enc(S[3], S[4]), round[1])
		# then we have the result of aes(S[7]) after 1 iteration
		round[0] = differentials.unaes(round[0])
		round[1] = differentials.unaes(round[1])
		# now just S[7] after 1 iteration, so xor with known s[7]
		round[0] = _xor(round[0], S[7])
		round[1] = _xor(round[1], S[3])
		# now we have aes(S[6]), after 0, so
		S[6] = differentials.unaes(round[0])
		S[2] = differentials.unaes(round[1])
	#print(S)
	print([x.hex() if x else '??' for x in S])

# now we just need to get S[1] and S[5].  luckily this isn't hard
chunk = zeroct[32:64]
fh, sh = chunk[:16], chunk[16:]
S[1] = _xor(fh, _xor(S[6], _and(S[2], S[3])))
S[5] = _xor(sh, _xor(S[2], _and(S[6], S[7])))

print(S)

write(b''.join(S)) # state = win

# PHASE 2: unicode errors.  start by leaking the original plaintext

while r.recvline() != b"That was rude! I won't encrypt any messages anymore!\n":
	pass

import re

id, aad, ct, tag = read(), read(), read(), read()

debuginfo = []

oracleuses = 0

def _oracle(ct):
	global debuginfo, oracleuses
	oracleuses += 1
	if oracleuses > 231:
		raise Exception("too many requests")
	while True:
		response = r.recvline()
		if response.startswith(b"DEBUG"):
			debuginfo.append(response)
			continue
		if response == b"--OK--\n":
			return None
		match = re.fullmatch(br"'ascii' codec can't decode byte 0x(\w+) in position (\d+): ordinal not in range\(128\)\n", response)
		if not match:
			continue
		return (int(match[2]), int(match[1], 16))

secret_pt = [None for _ in range(96)]

for i in range(0, 96): # section of plaintext to leak
	new_ct = bytes([x ^ 128 if j == i else x for j,x in enumerate(ct)])
	write(new_ct)
for i in range(0, 96):
	pos, c = _oracle(new_ct)
	assert pos == i
	secret_pt[i] = c ^ 128
secret_pt = bytes(secret_pt)
print("leaked plaintext:", secret_pt)

# using byte differentials to leak state, then recombine the same as above

def oracle(ct, chunk, sub):
	write(ct)
	res = _oracle(ct)
	if res == None or res[0] >= 16 * chunk + 4 * sub + 4:
		return None
	else:
		return (res[0] - 16 * chunk - 4 * sub, res[1] ^ secret_pt[res[0]])

S = [None for _ in range(5)]
for round in range(4):
	rr = [None for _ in range(16)]
	for sub, inds in enumerate(bins):
		for j, byt in enumerate(inds):
			seq, dec = differentials.p2diffs[j]
			lu = []
			for s in seq:
				new_ct = bytes([x ^ s if i == byt + 16 * round else x for i,x in enumerate(ct)])
				res = oracle(new_ct, 2 + round, sub)
				#print(sub, inds, j, byt, s, res)
				lu.append(res)
				if tuple(lu) in dec:
					rr[byt] = dec[tuple(lu)]
					#print(S0)
					break
			else:
				assert False
	if round == 0:
		S[0] = rr
	elif round == 1:
		# now at 1st round s[0]
		s10 = rr
		rr = _xor(_xor(rr, S[0]), secret_pt[16:32])
		S[4] = differentials.unaes(rr)
	elif round == 2:
		# now at 2nd round s[0]
		s20 = rr
		rr = _xor(s10, _xor(rr, secret_pt[32:48]))
		rr = differentials.unaes(rr)
		# now at 1st round s[4]
		s14 = rr
		rr = _xor(rr, S[4])
		S[3] = differentials.unaes(rr)
	elif round == 3:
		# now at 3rd round s[0]
		rr = _xor(s20, _xor(rr, secret_pt[48:64]))
		rr = differentials.unaes(rr)
		# now at 2nd round s[4]
		rr = _xor(rr, s14)
		rr = differentials.unaes(rr)
		# now at 1st round s[3]
		rr = _xor(rr, S[3])
		S[2] = differentials.unaes(rr)

# figure out S[1], however just like above this is easy
S[1] = _xor(ct[16:32], _xor(secret_pt[16:32], _xor(S[4], _and(S[2], S[3]))))

print(debuginfo)
print([''.join(x.to_bytes(1, 'little').hex() if x else "??" for x in S0) if S0 else "?" for S0 in S])
print(oracleuses)

if oracleuses < 231:
	r.sendline("challenge")

import challenge

ouraad = aad + secret_pt[:16]
cipher = aegis.Aegis128(bytes(16))
Send, ourct = cipher.raw_encrypt(S, challenge.DATA)
ourtag = cipher.finalize(Send, len(ouraad) * 8, len(challenge.DATA) * 8)

write(ourct) # ciphertext
write(ouraad) # aad
write(ourtag) # tag

r.interactive()

