# Crypto02

WhiteHat quals were kinda wack, but I managed to get third with Dice Gang.
There weren't many cool challenges, but I guess this was a somewhat interesting.

We're given a server that sends us a base64-encoded then encrypted then base64-encoded "question",
and we have to answer that question.  First thing to note: the encryption is in counter mode,
however the counter is just a constant nonce from the following lines, so every block of the plaintext
is XORed with the same encrypted nonce, so really we just have an XOR cipher with a repeating
16-byte key.

```python
def encrypt(s, nonce):
	s = b64encode(s)
	crypto = AES.new(key, AES.MODE_CTR, counter=lambda: nonce)
	return b64encode(crypto.encrypt(s))
```

To find this, we're given the following oracle.

```python
question = raw_input('Your question: ')
answer = raw_input('Your answer: ')
if question and answer:
	try:
		question = decrypt(question, session['nonce'])
		except Exception as e:
			return "Error"
```

So, we get to see if what we sent isn't valid base64 after we decrypt.  Python2's b64decode implementation
is wack as I discovered while solving this, so I figured I could just use epirical data to figure out
what base64 characters fail and succeed base64 decoding when XORed with a certain subset of bytes,
so we just check the example encryption we're given, XOR each character of it with a those bytes,
and figure out what it each character behaves like, so we can figure out the first base64 characters
after the decryption.  Then, we just XOR those with the first 16 bytes of the ciphertext, and we have
our pad.  It's just a matter of decrypting their question and sending the answer to them.  This is
fairly straightforward and implemented in `solve.py`.

## Addendum

Python2's base64 decoding is _weird_.  For example,

```python
from base64 import b64decode
import string

def d(x):
	try:
		return b64decode(x)
	except:
		return "Error!"

# any amount of equals signs is fine
for i in range(100):
	assert d("=" * i) == ""
	# even after data
	assert d("AA==" + "=" * i) == "\x00"

failSolos = [chr(x) for x in range(256) if d(chr(x)) == "Error!"]
# this is actually
base64alphabet = string.digits + string.ascii_letters + "+/"
assert set(failSolos) == set(base64alphabet)

# i think python2 b64decode just ignored non-b64 characters,
# this made working with this chal significantly more annoying
# and ruled a few ideas out
```


