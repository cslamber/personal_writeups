from aes_basics import *
import aegis

import random
import subprocess
import collections
import itertools
import functools
import struct

tes = [te0, te1, te2, te3]

# PHASE 1 differentials, leak entire block with 2 differentials.  the first
# differential is 1 in each byte, second is 2

p1dd = []

for diff in [1, 128]:
	inp = bytes([diff] * 16)
	vectors = [{te[a]^te[a^diff]: a for a in range(256)} for te in tes]
	p1dd += [(inp, vectors)]

def p1solve(diff, d):
	print("p1solve", diff, d)
	ret = set()
	for line in subprocess.check_output(["./brute", str(d), str(diff)]).strip().splitlines():
		ret.add(tuple(map(int, line.strip().split())))
	return ret

def unaes(aesed):
	def unround(end):
		out = subprocess.check_output(["./brute", "0", str(end)]).strip().splitlines()
		assert len(out) == 1
		return tuple(map(int, out[0].split()))
	s = [None for _ in range(16)]
	a,b,c,d = struct.unpack(">IIII", aesed)
	s[0], s[5], s[10], s[15] = unround(a)
	s[4], s[9], s[14], s[3] = unround(b)
	s[8], s[13], s[2], s[7] = unround(c)
	s[12], s[1], s[6], s[11] = unround(d)
	assert aes_enc(bytes(s), aesed) == bytes(16)
	return bytes(s)

#if __name__ == "__main__":
#	unaes(bytes([random.randrange(256) for _ in range(16)]))

# PHASE 2: create special single-byte differentials so that we leak via
# unicode errors.  these should always be 2-3 shots at most

def p2oracle(dat):
	b = struct.pack(">I", dat)
	for i,c in enumerate(b):
		if c >= 128:
			return (i,c)

def p2finddiff(table):
	unresolved = set(range(256))
	seq = []
	dec = dict()
	while unresolved:
		bestcand = None
		bestdec = None
		bestval = 0
		bestres = 256
		bestbackup = None
		for cand in range(256):
			orc=lambda b,c:p2oracle(table[b]^table[b^c])
			r = collections.defaultdict(list)
			for b in unresolved:
				r[tuple(orc(b,c) for c in seq + [cand])].append(b)
			cdec = {k: v[0] for k,v in r.items() if len(v) == 1}
			res = max(len(v) for v in r.values())
			if len(cdec) > bestval:
				bestval = len(cdec)
				bestcand = cand
				bestdec = cdec
			if res < bestres:
				bestbackup = cand
				bestres = res
		if bestval > 0:
			seq.append(bestcand)
			dec = {**dec, **bestdec}
			unresolved = unresolved - set(bestdec.values())
		else:
			seq.append(bestbackup)
	return seq, dec

p2diffs = [p2finddiff(te) for te in tes]

if __name__ == "__main__":
	print(p2finddiff(tes[1]))

