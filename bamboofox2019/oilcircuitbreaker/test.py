from ocb import OCB, Block
# this is just to figure out whether this was a legit
# implemention by testing test vectors

while True:
	choice = input("> ")
	if choice == "encrypt":
		key = Block.fromhex(input("key = ")).data
		nonce = Block.fromhex(input("nonce = "))
		plain = Block.fromhex(input("plain = "))
		cipher, tag = OCB(key).encrypt(nonce, plain)
		print(f"cipher = {cipher.hex()}")
		print(f"tag = {tag.hex()}")
	if choice == "decrypt":
		key = Block.fromhex(input("key = ")).data
		nonce = Block.fromhex(input("nonce = "))
		cipher = Block.fromhex(input("cipher = "))
		tag = Block.fromhex(input("tag = "))
		auth, plain = OCB(key).encrypt(nonce, cipher, tag)
		print(f"auth = {auth}")
		if auth:
			print(f"plain = {plain.hex()}")
