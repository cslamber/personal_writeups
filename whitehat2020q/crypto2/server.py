#!/usr/bin/env python2


# oh yeah, I also used a secret.py file that gave me garbage that works with this

from Crypto.Cipher import AES
import os, hashlib, json, sys, time, random, string
from base64 import b64encode, b64decode
from binascii import hexlify
import secret

key = secret.key

MAX_REQUEST = 1600
MAX_TIME = 800
session = {}


def ticket():
	s = ''.join(random.choice(string.printable) for i in range(4))
	print "Your ticket hash:", hashlib.sha1(s).hexdigest()
	res = raw_input("Input your ticket code: ")
	if res == s:
		return True
	exit()
def raw_input(promt):
	print promt,
	sys.stdout.flush()
	data = sys.stdin.readline().strip()
	return data

def get_challenge():
	question = secret.get_question()
	session['request_count'] = 0
	session['time'] = time.time()
	nonce = os.urandom(16)
	session['nonce'] = nonce
	print("PAD: " + b64encode(AES.new(key, AES.MODE_CTR, counter=lambda: nonce).encrypt(b"\x00"*16)))
	return encrypt(question, nonce)


def answer_challenge():
	if ('request_count' not in session) and ('nonce' not in session) and ('time' not in session):
		return "Get question first!"
	if (time.time() - session['time']) > MAX_TIME:
		print "Time out"
		exit()
	session['request_count'] += 1
	if session['request_count'] > MAX_REQUEST:
		print "Too much request"
		exit()
	question = raw_input('Your question: ')
	answer = raw_input('Your answer: ')
	if question and answer:
		try:
			question = decrypt(question, session['nonce'])
			# print question
		except Exception as e:
			return "Error"
	if question:
		return secret.check_answer(question, answer)
	return "None"

def encrypt(s, nonce):
	s = b64encode(s)
	crypto = AES.new(key, AES.MODE_CTR, counter=lambda: nonce)
	return b64encode(crypto.encrypt(s))

def decrypt(s, nonce):
	s = b64decode(s)
	crypto = AES.new(key, AES.MODE_CTR, counter=lambda: nonce)
	#print hexlify(crypto.decrypt(s))
	return b64decode(crypto.decrypt(s))

	

def banner():
	
	print "Welcome!! Find and answer the question to solve the challenge and get flag!"

def main():
	banner()
	while True:
		print "1. Get challenge\n2. Solve challenge"
		choice = raw_input('Your choice: ')
		if choice == '1':
			print get_challenge()
		elif choice == '2':
			print answer_challenge()
		else:
			print "Choice 1 or 2!"

if __name__ == '__main__':
	main()
