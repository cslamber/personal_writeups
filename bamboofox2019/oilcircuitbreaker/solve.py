from pwn import *
# this uses a modified Block that has .lsb(n) and .half()
from ocb import Block

#context.log_level = "debug"

FINAL = True

goal = Block(b"giveme flag.txt")
# we need to get
# cipher = e(Block.len(15) ^ L_2).msb(15) ^ goal
# tag = e(goal | e(Block.len(15) ^ L_2).lsb(1))


if FINAL:
	r = remote("bamboofox.cs.nctu.edu.tw", 25000)
else:
	r = process("./server.py", env = {})

# we're going to use all operations:
# 1. an encryption to get the pad we need as well as to set up for learning L
# 2. a decryption to find L
# 3. an encryption (different nonce) to get the tag

# all will be useful later
payload = Block()
payload |= Block.len(15) # e(Block.len(15) ^ L_2) ^ L_2
payload |= Block.len(15) # e(Block.len(15) ^ L_3) ^ L_3 
payload |= Block.len(16) # e(Block.len(16) ^ L_4) ^ L_4 
payload |= Block.len(16) # e(Block.len(16) ^ L_5) ^ L_5 
payload |= Block.zero() # e(Block.len(16) ^ L_6)
# S = Block.zero()
# T = e(L_6 ^ L_7)

r.sendlineafter("> ", "1")
r.sendlineafter("nonce = ", Block.zero().hex())
r.sendlineafter("plain = ", payload.hex())

r.recvuntil("cipher = ")
cipher = Block.fromhex(r.recvline()[:-1])
r.recvuntil("tag = ")
tag = Block.fromhex(r.recvline()[:-1])

# now for the decryption payload
# this is a mess and a disgrace, just trial and error lmao
payload = Block()
payload |= cipher[0] # Block.len(15)
payload |= cipher[1] # Block.len(15)
payload |= cipher[2] # Block.len(16)
payload |= cipher[3] # e(Block.len(16) ^ L_5) ^ e(Block.len(16) ^ L_5) ^ L_5 = L_5
# S = Block.len(16) ^ L_5
# T = e(L_5 ^ L_6 ^ Block.len(16) ^ L_5) = e(Block.len(16) ^ L_6)
# T = cipher[5]

r.sendlineafter("> ", "2")
r.sendlineafter("nonce = ", Block.zero().hex())
r.sendlineafter("cipher = ", payload.hex())
r.sendlineafter("tag = ", cipher[4].hex())

r.recvuntil("plain = ")
plain = Block.fromhex(r.recvline()[:-1])
L_5 = plain[3]
L = L_5.half().half().half().half()

# ok so now we need a known L that's new
# im going to use e(Block.len(16) ^ L_6) = cipher[4]
nL = cipher[4]
nonce = Block.len(16) ^ L_5.double()

# for the final round, we just need to get
# tag = e((goal | pad.lsb(1)) ^ L_2 ^ L_3)
# note that pad = e(Block.len(15) ^ L_2) = cipher[0] ^ L_2
pad = cipher[0] ^ L.double()

# to get the inner part, we do
inner = (goal | pad.lsb(1)) ^ L.double() ^ L.double().double()

payload = Block()
payload |= inner ^ nL.double() # e(inner ^ nL_2 ^ nL_2) ^ nL_2 = e(inner) nL_2 = tag ^ nL_2
payload |= Block.zero() # we don't care

r.sendlineafter("> ", "1")
r.sendlineafter("nonce = ", nonce.hex())
r.sendlineafter("plain = ", payload.hex())

r.recvuntil("cipher = ")
tag = Block.fromhex(r.recvline()[:-1])[0] ^ nL.double()

# and now finally for the win

r.sendlineafter("> ", "3")
r.sendlineafter("nonce = ", Block.zero().hex())
r.sendlineafter("cipher = ", (pad.msb(15) ^ goal).hex())
r.sendlineafter("tag = ", tag.hex())

r.interactive()

