#!/usr/bin/env python
#
# DNSChat - Proof of Concept Implementation (DNSCHAT-2)
#
# http://projects.bentasker.co.uk/jira_projects/browse/DNSCHAT.html
#
# Copyright (C) 2014 B Tasker
# Released under GNU GPL V2
# See http://www.gnu.org/licenses/gpl-2.0.html
#
#
# Dependancies (Ubuntu Package names)
# 	python-scapy
#	python-gnupg
#

import threading
import os
import sys
import time
import gnupg
import json
import dns.resolver
import random
import re
import getpass
import getopt


# Scapy likes to complain if there isn't an IPv6 route, so lets shut it up
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *


listener = None
listenerthread = None
cryptobj = None
debug = False


class ChatListen (threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		global listenerthread
		self.current_value = None
		self.running = True
		self.key = None
		self.debug = False
		self.buffer = {}


	def run(self):
		global listener
		while self.running:
			self.listen()

	def listen(self):
		sniff(filter="port 53",prn=self.process_pkt,timeout=10)

	def process_pkt(self,pkt):
		if DNSQR in pkt and pkt.dport == 53:

			# Break the query down into it's constituent parts
			eles = pkt[DNSQR].qname.split('.')

			seqid = eles[1]
			seqno = eles[2]

			# This is a somewhat restrictive requirement and could easily be improved, but it works well enough for a PoC
			match = re.search("^\d+$", eles[1])
			try: 
				x = match.group(0)
			except AttributeError: 
				return

			# Ignore messages that we've sent
			if int(eles[0]) == self.myid:
				return

			if debug:
				print 'Received part ' + str(eles[2]) + '/' + str(eles[3]) + ' for msg sequence ' +seqid+ ' from user ' + str(eles[0])


			# Create an entry in the dict if there isn't one already
			if self.buffer.has_key('seq'+seqid) is False:
				self.buffer['seq'+seqid] = {}
				self.buffer['seq'+seqid]['user'] = eles[0]
				self.buffer['seq'+seqid]['entries'] = {}
				self.buffer['seq'+seqid]['seqlen'] = eles[3]
				self.buffer['seq'+seqid]['output'] = False


			# Set the details for this entry
			self.buffer['seq'+seqid]['entries'][seqno] = eles[4]


			# Once the full despatch has been received, re-assemble and output.
			if len(self.buffer['seq'+seqid]['entries']) == int(self.buffer['seq'+seqid]['seqlen']) and self.buffer['seq'+seqid]['output'] is False:
				compiled = ''
				# Re-assemble the messages in order
				for key,value in sorted(self.buffer['seq'+seqid]['entries'].iteritems(), key=lambda key_value: int(key_value[0])):
					compiled += value


				#print 'Attempting to decrypt ' +compiled.decode('hex')
				clear =  self.cryptobj.decrypt(compiled)

				try:
					obj = json.loads(clear)
				except:
					# If we couldn't decrypt it, the key being used is probably wrong
					print '[Warning]: Received a message that could not be decrypted'
					self.buffer['seq'+seqid]['output'] = True # Prevent repetition of the warning
					return

				ts = time.strftime('%H:%M:%S', time.localtime(obj['t']))

				# Output the message (yes, this should be somewhere else really)
				print ''
				print ts +' [User ' + self.buffer['seq'+seqid]['user'] +']: ' +obj['m']
				print 'Enter a Message:'


				# Prevent the message from being output again (which it might be if the query returned NXDOMAIN)
				self.buffer['seq'+seqid]['output'] = True





class DNSChatCrypto():
	''' Very basic crypto class - doesn't do anything more spectacular than hand off to GnuPG
	'''

	def __init__(self,key):
		self.keystring = key
		self.gpg = gnupg.GPG()

	def encrypt(self,msg):
		''' Encrypt the message with a symmetric key (PKI would be trivial to implement here though

			We don't ascii armor as it has two major drawbacks

				- It increases the message size
				- The first characters of the hex encoded version are always the same (2d2d2d2d2d424547494e20504750204d45535341), makes it easy to identify

		'''
		crypted= self.gpg.encrypt(msg,None,passphrase=self.keystring,symmetric='AES256',armor=False)
		return crypted.data.encode('hex')
	


	def decrypt(self,ciphertext):
		return str(self.gpg.decrypt(ciphertext.decode("hex"),passphrase=self.keystring))



def main(argv):
	''' Starting point.....

	'''

	myid = False
	resolve = False
	domain = False
	charlimit = 63


	# Process the command-line arguments
	try:
		opts, args = getopt.getopt(argv, "vhr:i:d:c:", ["debug","help","resolver=","id=","domain-suffix=","char-limit="])
	except getopt.GetoptError:
		usage()
		sys.exit(2)


	for opt, arg in opts:
		if opt in ("-v","--debug"):
			global debug
			debug = True
		elif opt in ("-h","--help"):
			usage()
			sys.exit(2)
		elif opt in ("-r","--resolver"):
			resolve = dns.resolver.Resolver(configure=False)
			resolve.nameservers = [arg]
		elif opt in ("-i","--id"):
			if int(arg) > 0:
				myid = arg
		elif opt in ("-d","--domain-suffix"):
			domain = arg
		elif opt in ("-c","--char-limit"):
			charlimit = int(arg)

	if not myid:
		myid = random.randint(1,99)

	if not resolve:
		resolve = dns.resolver.Resolver()

	if not domain:
		domain = raw_input('Enter the domain to query: ')


	# Get things rolling
	launch(resolve,myid,domain,charlimit)



def usage():
	''' Output the usage information

	'''
	print ''
	print '-h/--help		Print this text'
	print '-r/--resolver=		DNS Resolver to use (e.g. --resolver=8.8.8.8)'
	print '-c/--char-limit=		The maximum number of characters to use per query (default 63 - max is also 63)'
	print '-i/--id=		Numeric ID to use'
	print '-d/--domain=		The domain to query (e.g. --domain=example.com)'
	print '-v/--debug		Use debug mode'
	return



def launch(resolve,myid,domain,charlimit):
	''' Launch the threads

		This used to be main() and then I dropped in support for command line arguments
	'''


	global cryptobj
	global listenerthread
	global debug


	if debug:
		print 'Running with the following values'
		print '	Resolver:' +str(resolve.nameservers)
		print '	My ID:' + str(myid)
		print '	Domain:' + str(domain)
		print ''


	# Get the passphrase to use
	key = getpass.getpass('Enter Symmetric passphrase to use for this session: ')

	cryptobj = DNSChatCrypto(key)
	myid = myid

	listenerthread = ChatListen()
	listenerthread.cryptobj = cryptobj
	listenerthread.myid = myid
	listenerthread.debug = debug
	listenerthread.start()
	seqid = random.randint(0,999)

	try:
		while True:
			msgstring = {}
			msg = raw_input('Enter a Message: ')
			epoch_time = int(time.time())		
			msgstring['t'] = epoch_time
			msgstring['m'] = msg

			# Encrypt the message
			ciphertext = cryptobj.encrypt(json.dumps(msgstring)) # Example:  {"msg": "A test", "time": 1421148145}

			testlen = len(str(myid)+'.'+str(seqid)+'.99.1000..'+domain) + charlimit

			while testlen >= 253 or charlimit > 63:
				# We're likely to hit a limit on DNS name length (63 bytes per label, 253 bytes for the entire domain name)
				charlimit -= 5
				testlen = len(str(myid)+'.'+str(seqid)+'.99.1000..'+domain) + charlimit
				if debug:
					print 'Charlimit lowered to ' +str(charlimit)
				if charlimit < 15:
					print '[System]: Available character length is getting low. Consider exiting and re-connecting'



			# Break the message down into suitable chunks
			charlimit # No more than 40 chars per request
			chunks = [ciphertext[i:i+charlimit] for i in range(0, len(ciphertext), charlimit)]

			TN = str(len(chunks)) # Calculate the number of requests that will be made

			
			for seqno, msg in enumerate(chunks):
				try:
					if debug:
						print 'Querying: ' + str(myid)+'.'+str(seqid)+'.'+str(seqno)+'.'+TN+'.'+str(msg)+'.'+domain
					# Send the query
					resp = resolve.query(str(myid)+'.'+str(seqid)+'.'+str(seqno)+'.'+TN+'.'+str(msg)+'.'+domain,'A').response
				except:
					# Don't raise an exception on NXDOMAIN
					continue


			# Output a copy of the text
			ts = time.strftime('%H:%M:%S', time.localtime(msgstring['t']))
			print ts +' [You]: ' +msgstring['m']

			# increment the sequence number
			seqid += 1

			


	except (KeyboardInterrupt, SystemExit):
		listenerthread.running = False
		print ''
		print 'Exiting....'
		listenerthread.join() # Let the thread finish



if __name__ == '__main__':
	try:
		main(sys.argv[1:])
	except (KeyboardInterrupt, SystemExit):
		print 'Exiting'
		sys.exit()

