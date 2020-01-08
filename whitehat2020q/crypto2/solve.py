from pwn import *
from hashlib import sha1
import string
from base64 import b64encode, b64decode

alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
alphabet = alphabet.encode()

context.log_level = "debug"
FINAL = True

compute_range = range(10, 100, 3 if FINAL else 1)

# precompute
ref = {}
for ind in range(16):
	ref[ind] = {}
	for j in alphabet:
		k = []
		for i in compute_range:
			check = list(b64encode("sice me the jklfadsjklfdskj deets".encode()))
			check[ind] = i ^ j
			check = bytes(check)
			try:
				b64decode(check)
				works = True
			except:
				works = False
			k += [works]
		assert tuple(k) not in ref[ind]
		ref[ind][tuple(k)] = j

if FINAL:
	r = remote("15.165.82.111", 1472)
else:
	r = process("./server.py", env = {})

# when we're using our test server I want to be able to debug the pad
if not FINAL:
	PAD = b""

# this pow takes forever so they basically forced us to test stuff against our own process
if FINAL:
	r.recvuntil("hash: ")
	targethash = r.recvline()[:-1]
	ticket = util.iters.mbruteforce(
		lambda x: sha1(x.encode()).hexdigest().encode() == targethash,
		string.printable, 4, "fixed")
	r.sendlineafter("ticket code: ", ticket)

def get_challenge():
	r.sendlineafter("Your choice: ", "1")
	if not FINAL:
		r.recvuntil("PAD: ")
		global PAD
		PAD = b64decode(r.recvline()[:-1])
	return b64decode(r.recvline().strip())

def answer_challenge(question, answer):
	r.sendlineafter("Your choice: ", "2")
	r.sendlineafter("Your question: ", b64encode(question))
	r.sendlineafter("Your answer: ", answer.encode())
	return r.recvline().strip()

# check if we don't error out when base64 decoding
def padded(question):
	return answer_challenge(question, "xddd") != b"Error"

chal = get_challenge()

assert padded(chal)

pad = []
for i in range(16):
	k = []
	for j in compute_range:
		cur = list(chal)
		cur[i] ^= j
		cur = bytes(cur)
		k += [padded(cur)]
	assert tuple(k) in ref[i]
	pad += [ref[i][tuple(k)] ^ chal[i]]

question = bytes([x^y for x,y in zip(pad*100, chal)])
print(b64decode(question))
print(b64encode(chal))

r.interactive()

