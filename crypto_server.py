# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author: McKoy Banton
# Last modified: 2023-11-22
# Version: 0.1.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES
from simplified_AES import *
import NumTheory 
from NumTheory import *


class RSAServer(object):
    
    def __init__(self, port, p, q):
        self.socket = socket.socket()
        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		#For storing the server's n in the public/private key
        self.pubExponent = None	#For storing the server's e in the public key
        self.privExponent = None	#For storing the server's d in the private key
        self.nonce = None
        # Call the methods to compute the public private/key pairs
        

    def send(self, conn, message):
        conn.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")

    def close(self, conn):
        print("closing server side of connection")
        try:
            conn.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            # Delete reference to socket object
            conn = None    

    def RSAencrypt(self, msg):
        """Encryption side of RSA"""
        """"This function will return (msg^exponent mod modulus) and you *must*"""
        """ use the expMod() function. You should also ensure that msg < n before encrypting"""
        """You will need to complete this function."""
        if (msg<self.modulus):
            RSAencryptM=NumTheory.expMod(msg,self.pubExponent,self.modulus)
            return RSAencryptM
        else:
            return -1

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you *must*"""
        """ use the expMod() function"""
        """You will need to complete this function."""
        RSAdecryptC=NumTheory.expMod(cText, self.privExponent, self.modulus)
        return RSAdecryptC

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext

    def generateNonce(self):
        """This method returns a 16-bit random integer derived from hashing the
            current time. This is used to test for liveness"""
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode('utf-8'))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

    def findE(self, phi):
        """Method to randomly choose a good e given phi"""
        """You will need to complete this function."""
        potential_e=random.randint(1, self.modulus-1)   
        gcd=NumTheory.gcd_iter(potential_e, phi)

        while (gcd>1):
                potential_e=random.randint(1, self.modulus-1)   
                gcd=NumTheory.gcd_iter(potential_e, phi)

        return potential_e
    
    def genKeys(self, p, q):
        """Generates modulus (n), phi(n), e, and d"""
        """You will need to complete this function."""
        self.modulus=p*q #n
        phi=(p-1)*(q-1)
        self.pubExponent=self.findE(phi)
        self.privExponent=NumTheory.ext_Euclid(phi,self.pubExponent)
        
        print("n: ",self.modulus)
        print("φ(n): ",phi)
        print("e: ",self.pubExponent)
        print("d: ",self.privExponent)
        print("ed mod φ(n):", (self.pubExponent*self.privExponent) % phi)

    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce()
        status = "102 Hello AES, RSA16 " + str(self.modulus) + " " + \
         str(self.pubExponent) + " " + str(self.nonce)
        return status

    def nonceVerification(self, decryptedNonce):
        """Verifies that the transmitted nonce matches that received
        from the client."""
        """You will need to complete this function."""
        if (int (self.nonce)==decryptedNonce):
            return True
        else:
            return False
    
    
    def start(self):
        """Main sending and receiving loop"""
        """You will need to complete this function"""
        
        while True:
            connSocket, addr = self.socket.accept()
            #self.socket.connect((self.address, self.port))
            
            msg = connSocket.recv(1024).decode('utf-8')
            print (msg)
            self.send(connSocket, self.clientHelloResp())
            
            msgSession= connSocket.recv(1024).decode('utf-8')
            print (msgSession)

            if (msgSession.startswith("103 SessionKey")):
                splitMsgSession=msgSession.split(" ")

                #decrypt session key using the private key
                sessionKey_Client=(int(splitMsgSession[2]))
                self.sessionKey=self.RSAdecrypt(sessionKey_Client)

                clientNonce= int (splitMsgSession[3])
                decryptClientNonce=self.AESdecrypt(clientNonce)
                
                if self.nonceVerification(decryptClientNonce)==True:
                    #104 Msg
                    self.send(connSocket, "104 Nonce Verified")
                    print("Nonce matched, sent 104 msg to client, and awaiting encrypted prime!")

                    primeMsgClient=connSocket.recv(1024).decode('utf-8')
                    print(primeMsgClient)

                    if (primeMsgClient.startswith("108 PrimesEncrypted")):
                        primeMsgClient=primeMsgClient.split(" ")
                        decryptPrime1=self.AESdecrypt( (int(primeMsgClient[2])) )
                        decryptPrime2=self.AESdecrypt( (int(primeMsgClient[3])) )
                        print("Prime 1 decrypt: ",decryptPrime1)
                        print("Prime 2 decrypt: ",decryptPrime2)

                        product_LCM=decryptPrime1*decryptPrime2
                        LCMmsg="109 CompositeEncrypted "+ str(self.AESencrypt(product_LCM))
                        self.send(connSocket, LCMmsg)

                        finalMsg=connSocket.recv(1024).decode('utf-8')
                        print(finalMsg)
                    else:
                        pass
                else:
                    #400 Msg
                    self.send(connSocket, "400 Error")
                    print("Nonce did not match, sent 400 msg to client")
                    self.close(connSocket)
                    break
            
            self.close(connSocket)
            break

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 2:
        print ("Please supply a server port.")
        sys.exit()
        
    HOST = ''		# Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print("Server of McKoy Banton")

    print ("""Enter prime numbers. One should be between 211 and 281,
    and the other between 229 and 307. The product of your numbers should
    be less than 65536""")
    p = int(input('Enter P: '))
    q = int(input('Enter Q: '))
    
    while (not (p>=211 and p<=281) ) or (not (q>=229 and q<=307) ) or (p*q>65536):
            print ("""Enter prime numbers. One should be between 211 and 281,
    and the other between 229 and 307. The product of your numbers should
    be less than 65536""")
            p = int(input('Enter P: '))
            q = int(input('Enter Q: '))
        
    server = RSAServer(PORT, p, q)
    server.genKeys(p, q);
    server.start()

if __name__ == "__main__":
    main()
