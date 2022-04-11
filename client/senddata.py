#Client side file transfer using TLS to Server
import socket, ssl, pprint
import os, time, sys
from cryptography.fernet import Fernet
import time

host = 'localhost'
sslPort = 5555
try:
 inputFile = sys.argv[1]
except:
 inputFile = 'test/64k'

print("sending ", inputFile)

def encryptFile(fileName,BASE_DIR,key):
	f = Fernet(key)
	file_data= ""
	#newFile = os.path.join(BASE_DIR, "new_".join(inputFile))
	encFile = fileName+ 'en'
	with open(fileName, "rb") as file:
		file_data = file.read()
		# encrypt data
	encrypted_data = f.encrypt(file_data)
	with open(encFile, "wb") as file:
		file.write(encrypted_data)
	return encFile
	


def send(host, sslPort, inputFile, CRT_FILE,keyIn):
	flag = 1
	fileToSend = open(inputFile, 'rb')
	
	data = fileToSend.read(1024)
	try: 
		#create socket to handle TCP packets from IPV4 addresses
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#custom settings:
		context = ssl.SSLContext(ssl.PROTOCOL_TLS)
		#certificate is required
		context.verify_mode = ssl.CERT_REQUIRED
		#Do not check host name matches since cert does not match domain name
		context.check_hostname = False
		#load CArsa.crt to verify server.crt is authentic
		context.load_verify_locations(CRT_FILE)
		#SSL version 2, 3 are insecure so they have been blocked
		context.options |= ssl.OP_NO_SSLv2
		context.options |= ssl.OP_NO_SSLv3
		#wrap soc in tls to ensure certificate is verified and used
		sslConn = context.wrap_socket(soc, server_hostname=host) 
		#connect to server via TCP on sslPort
		sslConn.connect((host, sslPort))
	except Exception as e:
		print("ec:", e)
		
		flag = 0
	
	while data and flag == 1:
		try:
			#send data to bound host
			sslConn.send(data)
			time.sleep(3)
			#read remaining bytes until EOF
			data = fileToSend.read(1024)
		except Exception as e:
			print("Got exception while sending :",e)
			break
	#close connection to server
	fileToSend.close()
	print('File ' + inputFile + ' sending complete')

if __name__ == "__main__":
	keyIn = Fernet.generate_key()
	keyfile = open("keyfile", "wb")
	keyfile.write(keyIn)
	sendData_tls(host,sslPort,inputFile,CRT_FILE,"testkey")
