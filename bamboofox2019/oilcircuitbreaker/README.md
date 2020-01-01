# Oil Circuit Breaker

I figured I'd start doing CTF challenge writeups in 2020, so last night into
this morning I checked out BambooFoxCTF since someone on my team mentioned it a day back,
looking for something I could solve and writeup.  Luckily, there was a symmetric crypto
challenge that seemed interesting, so I spent about 6-7 hours doing it.  Symmetric crypto
is pretty rare, so this challenge being an interesting symmetric crypto was a nice surprise.
It ended with 5 solves (not including me since I solved it after the competition ended),
making it the second highest point value on the competition after a pwn chal.

## Beginning

The challenge presents you with two files, `ocb.py` and `server.py`: `ocb.py` implements
the symmetric mode-of-operation we're going to be breaking, and `server.py` sets the rules
for how we break it.  `server.py` is pretty straight forward: one connection = one key, 
2 encryptions (must use
difference nonces), 1 decryption, and then we have to create a ciphertext/nonce/tag trio
that authenticated decrypts to `giveme flag.txt`.  The obstacle is that we are not allowed
to encrypt anything that contains `giveme flag.txt`.

`ocb.py` is much more interesting, it implements a (very useful) Block class which
contains a fair amount of utility with working with blocks that will be passed to/from
block ciphers, as well as an OCB class which implements 
[OCB](https://web.cs.ucdavis.edu/~rogaway/ocb/ocb-back.htm) over AES-128 (albiet with some
issues---I'm not sure what differences there are because I'm too lazy to check, but the test
vectors didn't work).  The important part is as follows

```python
class OCB:
    def __init__(self, key):
        self.aes = AES.new(key, AES.MODE_ECB)
    def e(self, x):
        y = Block(self.aes.encrypt(x.data))
        return y
    def d(self, y):
        x = Block(self.aes.decrypt(y.data))
        return x
    @bytes_block_bytes
    def encrypt(self, N, M):
        L = self.e(N)

        C = Block()
        S = Block.zero()
        for i in range(M.blocksize()):
            L = L.double()
            if i == M.blocksize() - 1:
                pad = self.e(Block.len(M[i].size()) ^ L)
                C |= pad.msb(M[i].size()) ^ M[i]
                S ^= pad ^ (C[i] | Block.zero(BLOCKSIZE - M[i].size()))
            else:
                C |= self.e(M[i] ^ L) ^ L
                S ^= M[i]

        L = L.double() ^ L
        T = self.e(S ^ L)

        return C, T

    @bytes_block_bytes
    def decrypt(self, N, C, T):
        L = self.e(N)

        M = Block()
        S = Block.zero()
        for i in range(C.blocksize()):
            L = L.double()
            if i == C.blocksize() - 1:
                pad = self.e(Block.len(C[i].size()) ^ L)
                M |= pad.msb(C[i].size()) ^ C[i]
                S ^= pad ^ (C[i] | Block.zero(BLOCKSIZE - C[i].size()))
            else:
                M |= self.d(C[i] ^ L) ^ L
                S ^= M[i]

        L = L.double() ^ L
        if T == self.e(S ^ L):
            return True, M
        else:
            return False, None
```

`L.double()` is a method that is equivalent to multiplying by `x` over a 128-bit
boolean polynomial mod ring.  That's not important other than it's reversible, and
I implemented the inverse in the Block class, which I'll paste here

```python
BLOCKSIZE = 16

class Block:
    def __init__(self, data = b''):
        self.data = data

    @classmethod
    def fromhex(cls, hx):
        return cls(unhexlify(hx))

    @classmethod
    def random(cls, size):
        return cls(urandom(size))

    @classmethod
    def len(cls, n):
        return cls(int(n * 8).to_bytes(BLOCKSIZE, 'big'))

    @classmethod
    def zero(cls, size = BLOCKSIZE):
        return cls(int(0).to_bytes(size, 'big'))

    def double(self):
        assert(len(self.data) == BLOCKSIZE)
        x = int.from_bytes(self.data, 'big')
        n = BLOCKSIZE * 8
        mask = (1 << n) - 1
        if x & (1 << (n - 1)):
            x = ((x << 1) & mask) ^ 0b10000111
        else:
            x = (x << 1) & mask
        return Block(x.to_bytes(BLOCKSIZE, 'big'))

    # mine
    def half(self):
        assert(len(self.data) == BLOCKSIZE)
        x = int.from_bytes(self.data, 'big')
        n = BLOCKSIZE * 8
        mask = (1 << n) - 1
        if x & 1:
            x = ((x ^ 0b10000111) >> 1) | (1 << (n - 1))
        else:
            x = x >> 1
        return Block(x.to_bytes(BLOCKSIZE, 'big'))

    def hex(self):
        return self.data.hex()

    def size(self):
        return len(self.data)

    def blocksize(self):
        return len(self.data) // BLOCKSIZE + (len(self.data) % BLOCKSIZE > 0)

    def msb(self, n):
        return Block(self.data[:n])

    # mine
    def lsb(self, n):
        return Block(self.data[-n:])
    def __or__(self, other):
        return Block(self.data + other.data)

    def __xor__(self, other):
        assert(len(self.data) == len(other.data))
        return Block(bytes([x ^ y for x, y in zip(self.data, other.data)]))

    def __eq__(self, other):
        return self.data == other.data
```

## Solving

The important qualities to note are that the last block of the plaintext
is only xored with the ciphertext (the pad is determined by an encryption of
the length of the last block and the L parameter --- in turn determined by the
nonce and the amount of blocks).  The tag is just an encryption of the L
parameter xor the xor of all the plaintexts.  Therefore, in order to get the
15-length target plaintext, we must have the cipher and the tag which are
```python
goal = Block(b"giveme flag.txt")
# cipher = e(Block.len(15) ^ L_2).msb(15) ^ goal
# tag = e(goal | e(Block.len(15) ^ L_2).lsb(1))
# My notation for L is that L_1 = e(Nonce), L_n.double() = L_(n+1), and
# L_(n+1).half() = L_n
```


So after a lot of thinking about this, I became fairly set on one idea:
1. Use the first encryption to get the pad and setup for figuring out L
2. Use the decryption (same nonce) to find L
3. Use the second encryption (different known nonce) to get the tag.

For the first encryption, we know that we want the first block to be
`Block.len(15)` so we can figure out the pad once we know L.  Everything
else we're going to ignore for the time being since the decryption controls
what we want to encrypt here.

The decryption is much more tricky.  In order to get information from the decryption,
we need to know the tag in advance, so we have to construct something that makes
the tag something we know from encryption.

Things we need in the decrypted plaintext to make decryption work:
1. Block.len(15) so we know the pad
2. Block.len(15) again so they xor out to make the tag easier
3. Some L parameter so we know L.
4. Something to make the tag work.

The first two of these are straightforward, we just make the the first two blocks
of the plaintext we encrypt `Block.len(15)` and then also make those the first
two blocks of the decryption.

For the next, we're going to be more creative.  Let's use 4 blocks since that's
the amount of things we need and I also know it works in hindsight.  Then, we
have the tag in the decryption is equal to `e(L_5 ^ L_6 ^ S)` where S is the xor
of all the plaintext blocks.  Since `M[0] = M[1] = Block.len(15)` from before,
this gives us `tag = e(L_5 ^ L_6 ^ M[2] ^ M[3]`.  Remember, we want one of the M
blocks to be some L value, so wouldn't it be nice if we could get it to be
either `L_5` or `L_6` so stuff would cancel out?

Let's try to get `L_5`.  How would we do this?  Well, the last block of the encryption
is weird, so let's look at that.  We have `M[3] = C[3] ^ e(Block.len(C[3]) ^ L_5)`.  As
a side note, there's no point in making `M[3]` less than the full block size since
it just loses us control/information (and we want `M[3] = L_5`, remember), so with
that we get `M[3] = L_5 = C[3] ^ e(Block.len(16) ^ L_5)`.  Wait.  So
`C[3] = L_5 ^ e(Block.len(16) ^ L_5)` helps us a ton.  This value is the exact pattern
we get from encryption of a normal block of value `Block.len(16)`, specifically the
4th block.  Since this needs to be a normal block, say we have 5 blocks in the payload
we're encrypting, with the 4th block being `Block.len(16)`.  This is doable.

Cool, so now we have `M[3] = L_5` and we're basically done.

| Block | Thing to Encrypt | Encrypts to                    | Thing to Decrypt | Decrypts to                                                      | XOR of Decrypteds    |
|-------|------------------|--------------------------------|------------------|------------------------------------------------------------------|----------------------|
| 0     | Block.len(15)    | C[0]                           | C[0]             | Block.len(15)                                                    | Block.len(15)        |
| 1     | Block.len(15)    | C[1]                           | C[1]             | Block.len(15)                                                    | Block.zero()         |
| 2     | Block.len(16)    | C[2]                           | C[2]             | Block.len(16)                                                    | Block.len(16)        |
| 3     | Block.len(16)    | C[3]                           | C[3]             |  e(Block.len(16) ^ L\_5) ^ e(Block.len(16) ^ L\_5) ^ L\_5 = L_\5 | Block.len(16) ^ L\_5 |
| 4     | Block.zero()     | C[4] = e(Block.len(16) ^ L\_6) |                  |                                                                  |                      |
| TAG   |                  | Garbage                        | C[4]             | e(Block.len(16) ^ L\_6)                                          |                      |


Just get `L_1 = L_5.half().half().half().half()`.

With our final encryption, we just reconstruct the pad as `C[0] ^ L_1.double()`, which we will
xor with the goal to get our ciphertext for the win.  We just need to get
`e((goal | pad.lsb(1)) ^ L_2 ^ L_3)`.  Get a new nonce/L by knowing that
`e(Block.len(16) ^ L_6) = cipher[4]`.  So our `newnonce = Block.len(16) ^ L_5.double()` and
`nL = cipher[4]`.  Finally, we get the encryption we want by sending
`(goal | pad.lsb(1)) ^ L_2 ^ L_3 ^ nL_2` as the first block of the payload so
the first block of the cipher will be `e((goal | pad.lsb(1)) ^ L_2 ^ L_3 ^ nL_2 ^ nL_2) ^ nL_2`
which we then xor with `nL.double()` to get the tag we want.

Just send the original nonce, the ciphertext and the tag we just made to the execute function
on the server for the flag.  Finally.

`BAMBOOFOX{IThOUgHtitWAspRoVaBles3cuRE}`

The attached source files with a lot of the comments I used to track what I was
doing as I figured this out are in this directory as well.

