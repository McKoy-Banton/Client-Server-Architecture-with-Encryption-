# Client to implement simplified RSA algorithm and then subsequently send
# encrypted prime numbers to a server. The client says hello to the server
# and indicates
# which cryptographic algorithms it can support. The server picks one
# asymmetric key and one symmetric key algorithm and then responds to the
# client with its public key and a nonce. The client generates a symmetric
# key to send to the server, encrypts the symmetric key with the public key,
# and then encrypts the nonce with the symmetric key.
# If the nonce is verified, then the server will send the "106 Nonce Verified"
# message.

import socket
import math
import random
import sys
import simplified_AES
from simplified_AES import *
import NumTheory
from NumTheory import *
# Author: McKoy Banton
# Last modified: 2023-11-22
# Version: 0.1
#!/usr/bin/python3

class RSAClient:
    def __init__(self, address, port):
        self.address = address
        self.port = int(port)
        self.socket = socket.socket()
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		    #For storing the server's n in the public key
        self.serverExponent = None	#For storing the server's e in the public key
        self.nonce=None             #For storing the nonce sent by the server in 102 Hello msg
        self.prime1=0
        self.prime2=0
    def connect(self):
        self.socket.connect((self.address, self.port))

    def send(self, message):
        self.socket.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Server is unavailable")

    def close(self):
        print("closing connection to", self.address)
        try:
            self.socket.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.address}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None

    def RSAencrypt(self, msg): 
        """"This function will return (msg^exponent mod modulus) and you *must*"""
        """ use the expMod() function. You should also ensure that msg < n before encrypting"""
        """You will need to complete this function."""
        if (msg<self.modulus):
            encrypt=NumTheory.expMod(msg,self.serverExponent,self.modulus)
            return encrypt
        else:
            return -1

    def computeSessionKey(self,modulus):
        """Computes this node's session key"""
        self.sessionKey = random.randint(1, modulus-1)#appended the 2nd arg to modulus-1

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext
    
    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)
    
    def serverHello(self):
        status = "101 Hello 3DES, AES, RSA16, DH16"
        return status

    def sessionKeyMsg(self, nonce):
        """Function to generate response string to server's hello"""
        msg="103 SessionKey "+str(self.RSAencrypt(self.sessionKey))+" "+str(self.AESencrypt(nonce))

        return msg

    def getPrime(self):
        primeLst=[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 
                  101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 
                  173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251]
        self.prime1=int (input("Enter your first prime # from 1 to 255: "))
        self.prime2=int(input("Enter your second prime # from 1 to 255: "))

        while(self.prime1 not in primeLst) or (self.prime2 not in primeLst):
            if (self.prime1 not in primeLst):
                self.prime1=int (input("Enter your first prime # from 1 to 255: "))
           
            elif(self.prime2 not in primeLst):
                self.prime2=int(input("Enter your second prime # from 1 to 255: "))

    def start(self):
        """Main sending and receiving loop for the client"""
        print("Sending and Receiving Hello Msg")
        self.connect()
        self.send(self.serverHello())
        print("\n")
        self.read()
        print(self.lastRcvdMsg)

        #102 Hello Msg.
        if (self.lastRcvdMsg.startswith("102 Hello")):
            lastMsg=self.lastRcvdMsg.split()          
            self.modulus=int (lastMsg[4])
            self.serverExponent=int (lastMsg[5])
            nonce=int (lastMsg[6])

            print("*Sending and Receiving Session Key*")
            self.computeSessionKey(self.modulus)
            self.send(self.sessionKeyMsg(nonce))

            self.read()
            print(self.lastRcvdMsg)

            if (self.lastRcvdMsg.startswith("400 Error")):
                self.close()

            #If the nonce matches on client and server
            elif(self.lastRcvdMsg.startswith("104 Nonce Verified")):
                
                #Sending the 108 Prime message
                print("*Sending prime and receiving LCM*")
                self.getPrime()
                print("Prime numbers entered are: ", self.prime1, self.prime2)

                print("Sent Prime")
                primeMsg="108 PrimesEncrypted "+ str(self.AESencrypt(self.prime1))+ " "+str(self.AESencrypt(self.prime2))
                self.send(primeMsg)
                LCM_client=self.prime1*self.prime2
                LCM_client=(LCM_client)
                

                self.read()
                print(self.lastRcvdMsg)
                
                #Response from server about the 108 prime message
                if (self.lastRcvdMsg.startswith("109 CompositeEncrypted")):
                    LCM_server= self.lastRcvdMsg.split(" ") 
                    LCM_server_encrypt=int (LCM_server[2])
                    LCM_server_decrypt=int (self.AESdecrypt(LCM_server_encrypt))
                    
                    print("The lcm from server is :",LCM_server_decrypt)
                    
                    #Client sending 200 or 400 message based on the composite number.
                    print("*Send 200/400 msg and closing socket*")
                    if (LCM_client==LCM_server_decrypt):
                        self.send("200 OK")
                        print("Sent 200 OK")
                    else:
                        self.send("400 Error")
                        print("Sent 400 Error")
                        pass
                else:
                    print("Unexpected message at this stage it expected 109 msg")
        #end of if block for successful connection
        self.close()
        #pass


def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print ("Please supply a server address and port.")
        sys.exit()
    print("Client of McKoy Banton")
    serverHost = str(args[1])       # The remote host
    serverPort = int(args[2])       # The same port as used by the server

    client = RSAClient(serverHost, serverPort)
    try:
        client.start()
    except (KeyboardInterrupt, SystemExit):
        exit()

if __name__ == "__main__":
    main()
