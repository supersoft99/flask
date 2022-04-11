#Server side of file transfer using TLS
#Load Server Certificate to be shared via TLS handshake to client

import socket, ssl
import threading
import os
import time

BASE_DIR = './'

def decryptFile(fileName,key):
	f = Fernet(key)
	file_data= ""
	encFile = fileName+ 'en'
	with open(fileName, "rb") as file:
		file_data = file.read()
		# decrypt data
	decrypted_data = f.decrypt(file_data)
	with open(encFile, "wb") as file:
		file.write(decrypted_data)
	return encFile
	


def recv_timeout(the_socket,timeout=2):
	#make socket non blocking
	the_socket.setblocking(0)
	f = open('data.txt' , 'wb')
	#total data partwise in an array
	data='';
	
	#beginning time
	begin=time.time()
	while 1:
	#if you got some data, then break after timeout
		if time.time()-begin > timeout:
			break
		
		#if you got no data at all, wait a little longer, twice the timeout
		elif time.time()-begin > timeout*2:
			break
		
		#recv something
		try:
			data = the_socket.recv(8192)
			if data:
				f.write(data)
				#change the beginning time for measurement
				begin=time.time()
			else:
				#sleep for sometime to indicate a gap
				time.sleep(0.1)
		except:
			pass
	
	#join all parts to make final string

	keyfile = open("keyfile", "rb")
	key = keyfile.read(keyIn)
	print(key)
	decryptFile('data.txt', key)
	return 


def deal_with_client(stream, f):
	print('-----------------------------------------\n')
	while True:
		#read from stream and store
		data = stream.recv(1024)
		if not data:
			break
		else:
			#write data from stream.recv(..) to file
			f.write(data)
	print('End Of File received, closing connection...')
	print('-----------------------------------------\n')
	f.close()

def createConn(host,port):
	#create socket object
	sockServer = socket.socket()
	#bind host name to socket on pot number
	sockServer.bind(('0.0.0.0', port))
	#socket listening for up to 5 connections
	sockServer.listen(5)
	return sockServer

def startServer():
	index = 1
	CERT_DIR = os.path.join(BASE_DIR,"server.crt") 
	KEY_DIR = os.path.join(BASE_DIR, "server.pem")
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile=CERT_DIR, keyfile= KEY_DIR)
	#SSL version 2, 3 are insecure so they have been blocked
	context.options |= ssl.OP_NO_SSLv2
	context.options |= ssl.OP_NO_SSLv3
	bSocket = createConn('0.0.0.0',5555)
	while True:
		newSocket, fromaddr = bSocket.accept()
		streamSock = context.wrap_socket(newSocket, server_side=True)
		#open file to write data to
		#Prints IP address of Client
		print("'Connection established from " + str(fromaddr))
		try:
			#initalise thread to run deal_with_client(..) function
			p1 = threading.Thread(target=recv_timeout, args=(streamSock, 2))
			#start thread
			p1.start()
		except Exception as err:
			print('\n Error in handling client\n', err)
			break
	print('\n-----------------------------------------')
	print('Server shutting down...\n')

startServer()
