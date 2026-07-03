import argparse
import sys
import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15

import os
import random

#For fun 
import time

debug_levels = {
    "ERROR": 0,
    "WARN": 1,
    "INFO": 2,
    "DEBUG": 2,
    "FUN": 2
}

# Liste de nombre premier avec un de leur générateur.
# Cette liste sert ici d'exemple, les nombres premiers utilisés ici ne sont pas assez grand pour être sécurisé.
prime_number_data_base = [ (100003, 5), (100019, 2), (100043, 3), (100049, 6),
                           (100057, 2), (100069, 11), (100103, 7), (100109, 2),
                           (100129, 3), (100151, 6), (100153, 2), (100169, 17),
                           (100183, 3), (100189, 5), (100193, 2), (100207, 3),
                           (100213, 7), (100237, 13), (100267, 3), (100271, 2),
                           (100279, 6) ]


class SecureCommunicationApp:
    def __init__(self, role, host='127.0.0.1', port=65432, debug_level=0):
        self.role = role
        self.host = host
        self.port = port
        self.debug_level = debug_level
        self.username = role
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def log(self, message, debug_level):
        """Utility function for logging messages with different levels."""
        lvl_int = debug_levels[debug_level]
        if lvl_int > self.debug_level:
            return 
        
        if lvl_int == 0:
            print(f"\033[91m[{debug_level}] {message}\033[0m") # Red text
        elif lvl_int == 1:
            print(f"\033[93m[{debug_level}] {message}\033[0m") # Yellow text
        elif lvl_int == 2:
            print(f"\033[0;36m[{debug_level}] {message}\033[0m") # Blue text
        else:
            print(f"{debug_level} {message}")

    def start(self):
        if self.role == 'server':
            self.start_server()
        elif self.role == 'client':
            self.start_client()
        else:
            self.log("Invalid role specified. Use --server or --client.", "ERROR")

    def start_server(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.log(f"Server listening on {self.host}:{self.port}", "INFO")
        client_socket, addr = self.socket.accept()
        self.log(f"Connection established with {addr}", "INFO")
        self.handle_connection(client_socket, server_mode=True)

    def start_client(self):
        self.socket.connect((self.host, self.port))
        self.log(f"Connected to server at {self.host}:{self.port}", "INFO")
        self.handle_connection(self.socket, server_mode=False)

    def handle_connection(self, conn_socket, server_mode):
        try:
            # Placeholder for key exchange
            self.key_exchange(conn_socket)
            if self.certificat_exchange(conn_socket, server_mode) :
                if self.diffie_hellman(conn_socket, server_mode) == False :
                    self.log("Something went wrong in the Diffie-Hellman algo", "ERROR")
                else :
                    self.log(f"Communication tunnel open" , "DEBUG")
            else :
                self.log("Something went wrong in the certificat exchanges", "ERROR")

            while True:
                if server_mode:
                    # Getting the symetric key from the previous protocole
                    key_symetric = open('public_DH.pem', "rb").read()
                    aes = key_symetric[:16]
                    hmac = key_symetric[16:]

                    # Initialisation of the counter
                    server_counter = 0

                    # Server receiving a message
                    data = conn_socket.recv(1024)
                    if not data:
                        break
                    self.log(f"Received (encrypted): {data}" , "DEBUG")

                    # Placeholder for decrypting the message
                    server_counter += 1
                    message = self.unprotect_message(data, server_counter, aes, hmac)
                    print(f"Received: {message.decode()}")

                    if (message == b"DONE"):
                        server_counter += 1
                        response = self.protect_message(b"Communication Done", server_counter, aes, hmac)
                        conn_socket.sendall(response)
                        self.log(f"Sent: {response}" , "DEBUG")
                        os.remove("receiver.pem") 
                        os.remove("public_DH.pem") 
                        break

                    # Send an acknowledgment (protected)
                    server_counter += 1
                    response = self.protect_message(b"ACK", server_counter, aes, hmac)
                    conn_socket.sendall(response)
                    self.log(f"Sent: {response}" , "DEBUG")
                else:
                    # Getting the symetric key from the previous protocole
                    key_symetric = open('public_DH.pem', "rb").read()
                    aes = key_symetric[:16]
                    hmac = key_symetric[16:]

                    # Initialisation of the counter
                    client_counter = 0

                    # Client sending a message
                    message = input("Enter message to send: ").encode()
                    client_counter += 1
                    encrypted_message = self.protect_message(message, client_counter, aes, hmac)
                    conn_socket.sendall(encrypted_message)
                    self.log(f"Sent: {encrypted_message}" , "DEBUG")

                    # Receive a response from the server
                    data = conn_socket.recv(1024)
                    if not data:
                        break

                    # Placeholder for decrypting the response
                    self.log(f"Server response (encrypted): {data}" , "DEBUG")
                    client_counter += 1
                    response = self.unprotect_message(data, client_counter, aes, hmac)
                    print(f"Server response: {response.decode()}")
                    if (response == b"Communication Done"):
                        os.remove("receiver.pem")
                        os.remove("public_DH.pem") 
                        break

        except Exception as e:
            self.log(f"An error occurred: {e}", "ERROR")
        finally:
            conn_socket.close()

############################# Key exchange #####################################

    def key_exchange(self, conn_socket):
        public_key = open("public.pem").read()
        message = public_key.encode()
        conn_socket.sendall(message)
        receive_key = conn_socket.recv(1024)
        with open("receiver.pem", "wb") as f:
            f.write(receive_key)
        self.log(f"Public Key Received" , "DEBUG")

##################### Vérification certificat + signature ######################

    def isCertificatValide(self, certificat):
        """
        Overly complex function that simulates certificate verification.
        It performs complicated mathematical calculations, random tests,
        and other operations to ultimately do nothing and return True.
        """
        self.log("Initializing verification process...", "FUN")

        # Step 1: Generate random matrices and multiply them
        self.log("Multiplying random matrices to test the robustness of the certificate...", "FUN")
        matrice_1 = [[random.randint(0, 100) for _ in range(10)] for _ in range(10)]
        matrice_2 = [[random.randint(0, 100) for _ in range(10)] for _ in range(10)]
        resultat = [[sum(a * b for a, b in zip(row, col)) for col in zip(*matrice_2)] for row in matrice_1]
        self.log("Multiplication completed. Verification... Ok!", "FUN")

        # Step 2: Generate a dummy hash
        self.log("Generating a digital fingerprint of the certificate...", "FUN")
        hash_certificat = sum(ord(c) for c in str(certificat)) ** 2 % 999999
        self.log(f"Computed digital fingerprint : {hash_certificat}", "FUN")

        # Step 3: Simulate network latency
        self.log("Simulating a secure network connection for authentication...", "FUN")
        for i in range(3):
            self.log(f"Connecting to the verification gateway ({i+1}/3)...", "FUN")
            time.sleep(0.5)  # Pause inutile pour simuler un réseau lent
        self.log("Connection established. Verifying...", "FUN")

        # Step 4: Random test that does nothing
        self.log("Running random tests...", "FUN")
        tests_reussis = all(random.choice([True, True, True]) for _ in range(10000))
        self.log("Tests completed: all random tests passed.", "FUN")

        # Final step: Triumphantly return True
        self.log("All (useless) verification criteria have been successfully met.", "FUN")
        self.log("Certification validated ✅.", "FUN")
        return True

    def verif_sign(self, data, signature) :
        key = RSA.importKey(open('receiver.pem').read())
        data_hash = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(data_hash, signature)
            self.log("The signature is valid." , "DEBUG")
            return True
        except (ValueError, TypeError):
            self.log("The signature is not valid." , "DEBUG")
            return False
    
########################### Signature ##########################################

    def signature(self, message) :
        hash = SHA256.new(message)
        key = RSA.importKey(open('key.pem').read())
        signature_msg = pkcs1_15.new(key).sign(hash)
        return signature_msg

########################### Certificat exchange ################################

    def certificat_exchange(self, conn_socket, server_mode) :
        if server_mode :
            # Receiving certificat
            receive_certificat = ""
            receive_certificat_protect = conn_socket.recv(256)
            receive_certificat_block = self.unprotect_message_RSA(receive_certificat_protect).decode()
            while receive_certificat_block != "END" :
                receive_certificat += receive_certificat_block
                receive_certificat_protect = conn_socket.recv(256)
                receive_certificat_block = self.unprotect_message_RSA(receive_certificat_protect).decode()
            self.log("Client Certifica Received" , "DEBUG")

            # Receiving signature plus verification
            receive_signature = conn_socket.recv(1024)
            self.log("Client Signature Received" , "DEBUG")
            if self.verif_sign(receive_certificat.encode(), receive_signature) == False :
                return False

            # Fake verification of certificat plus sending server + client certificat 
            if self.isCertificatValide(receive_certificat) :
                # Server certificat
                certificat = open("cert.pem").read().encode()
                certificat_protect_block = self.protect_message_RSA(certificat) 
                for i in range(len(certificat_protect_block)):
                    conn_socket.sendall(certificat_protect_block[i])
                self.log("Certificat Send" , "DEBUG")
                # Client certificat
                certificat_protect_block = self.protect_message_RSA(receive_certificat.encode())
                for i in range(len(certificat_protect_block)):
                    conn_socket.sendall(certificat_protect_block[i])
                self.log("Client Certificat Send" , "DEBUG")

            # Sending signature
                send_both_certificat = certificat.decode() + receive_certificat
                conn_socket.sendall(self.signature(send_both_certificat.encode()))
                self.log("Signature Send" , "DEBUG")
        else :
            # Sending client certificat
            certificat = open("cert.pem").read().encode()
            certificat_protect_block = self.protect_message_RSA(certificat) 
            for i in range(len(certificat_protect_block)):
                conn_socket.sendall(certificat_protect_block[i])
            self.log("Certificat Send" , "DEBUG")

            # Sending signature
            signature_sent = self.signature(certificat)
            conn_socket.sendall(signature_sent)
            self.log("Signature Send" , "DEBUG")

            # Receiving server certificat
            receive_server_certificat = ""
            receive_certificat_protect = conn_socket.recv(256)
            receive_certificat_block = self.unprotect_message_RSA(receive_certificat_protect).decode()
            while receive_certificat_block != "END" :
                receive_server_certificat += receive_certificat_block
                receive_certificat_protect = conn_socket.recv(256)
                receive_certificat_block = self.unprotect_message_RSA(receive_certificat_protect).decode()
            self.log("Server Certifica Received" , "DEBUG")

            # Receiving own certificat
            receive_own_certificat = ""
            receive_certificat_protect = conn_socket.recv(256)
            receive_certificat_block = self.unprotect_message_RSA(receive_certificat_protect).decode()
            while receive_certificat_block != "END" :
                receive_own_certificat += receive_certificat_block
                receive_certificat_protect = conn_socket.recv(256)
                receive_certificat_block = self.unprotect_message_RSA(receive_certificat_protect).decode()
            self.log("Own Certifica Received" , "DEBUG")

            # Receiving signature plus verification
            receive_both_certificat = receive_server_certificat + receive_own_certificat
            receive_signature = conn_socket.recv(1024)
            self.log("Server Signature Received" , "DEBUG")
            if self.isCertificatValide(receive_server_certificat) == False :
                return False
            if self.verif_sign(receive_both_certificat.encode(), receive_signature) == False :
                return False
        return True

############################### Diffie-Hellman #################################

    def diffie_hellman(self, conn_socket, server_mode):
        rand = random.SystemRandom()
        if server_mode :
            # Receiving the prime number and the gen
            receive_prime_protect = conn_socket.recv(256)
            receive_gen_protect = conn_socket.recv(256)
            receive_prime = self.unprotect_message_RSA(receive_prime_protect).decode()
            receive_gen = self.unprotect_message_RSA(receive_gen_protect).decode()
            self.log("Prime number plus gen of Diffie-Hellman Received" , "DEBUG")

            # Receiving the signature + verification
            prime_gen = receive_prime + receive_gen
            receive_signature = conn_socket.recv(256)
            self.log("Diffie-Hellman Signature Received" , "DEBUG")
            if self.verif_sign(prime_gen.encode(), receive_signature) == False :
                return False
            
            # Generation symetric key
            p = int(receive_prime)
            g = int(receive_gen)
            b = rand.randrange(2, p - 1)  # private key
            B = pow(g, b, p)  # public key

            # Sending public symetric key
            key = RSA.importKey(open('receiver.pem').read())
            cipher = PKCS1_OAEP.new(key)
            cipherPublicKey = cipher.encrypt(str(B).encode())
            conn_socket.sendall(cipherPublicKey)
            conn_socket.sendall(self.signature(str(B).encode()))

            # Receiving public symetric key of the Client
            A_protect = conn_socket.recv(256)
            A = self.unprotect_message_RSA(A_protect)
            A_signature = conn_socket.recv(256)
            if self.verif_sign(A, A_signature) == False :
                return False
            symetric_key = str(pow(int(A.decode()), b, p)).encode()
            symetric_key_hash = SHA256.new(symetric_key).digest()
            # Sha256 will give us a 32 bytes key from our number, with this we
            # will be able to have two key, one for aes the other for the hmac
            # aes_key = symetric_key_hash[:16]
            # hmac_key = symetric_key_hash[16:]
            with open("public_DH.pem", "wb") as f:
                f.write(symetric_key_hash)
            self.log("Public Symetric Key Calculate" , "DEBUG")
        else :
            # Sending prime number and gen choose randomly in the "public" data base
            set_prime_gen = rand.randrange(0, len(prime_number_data_base)) 
            key = RSA.importKey(open('receiver.pem').read())
            cipher = PKCS1_OAEP.new(key)
            p = prime_number_data_base[set_prime_gen][0]
            g = prime_number_data_base[set_prime_gen][1]
            prime = str(p)
            gen = str(g)
            cipherPrime = cipher.encrypt(prime.encode())
            cipherGen = cipher.encrypt(gen.encode())
            conn_socket.sendall(cipherPrime)
            conn_socket.sendall(cipherGen)
            self.log("Prime number plus gen of Diffie-Hellman Send" , "DEBUG")

            # Signature
            prime_gen = prime + gen
            conn_socket.sendall(self.signature(prime_gen.encode()))
            self.log("Signature Diffie-Hellman Send" , "DEBUG")

            # Generation symetric key
            a = rand.randrange(2, p - 1)  # private key
            A = pow(g, a, p)  # public key

            # Sending public symetric key
            cipherPublicKey = cipher.encrypt(str(A).encode())
            conn_socket.sendall(cipherPublicKey)
            conn_socket.sendall(self.signature(str(A).encode()))

            # Receiving public symetric key of the Server
            B_protect = conn_socket.recv(256)
            B = self.unprotect_message_RSA(B_protect)
            B_signature = conn_socket.recv(256)
            if self.verif_sign(B, B_signature) == False :
                return False
            symetric_key = str(pow(int(B.decode()), a, p)).encode()
            symetric_key_hash = SHA256.new(symetric_key).digest()
            with open("public_DH.pem", "wb") as f:
                f.write(symetric_key_hash)
            self.log("Public Symetric Key Calculate" , "DEBUG")
        return True
            
########################### encryption Rsa #####################################

    def protect_message_RSA(self, message):
        key = RSA.importKey(open('receiver.pem').read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = []
        # Sending by block because the certificat is to long to be send directly
        msg_nb_blocks = len(message)//128
        for i in range(msg_nb_blocks) :
            ciphertext.append(cipher.encrypt(message[i*128:(i+1)*128]))
        ciphertext.append(cipher.encrypt(message[msg_nb_blocks*128:]))
        ciphertext.append(cipher.encrypt(b"END"))
        return ciphertext

    def unprotect_message_RSA(self, data):
        key = RSA.importKey(open('key.pem').read())
        cipher = PKCS1_OAEP.new(key)
        message = cipher.decrypt(data)
        return message
    
########################### encryption symetrique ##############################

    def protect_message(self, message, counter, aes, hmac):
        cipher = AES.new(aes, AES.MODE_CTR)

        binerie_counter = (counter).to_bytes(4, byteorder='little')

        message_counter = binerie_counter + message 

        ciphertext = cipher.encrypt(message_counter)

        hmac = HMAC.new(hmac, digestmod=SHA256)
        tag = hmac.update(cipher.nonce + ciphertext).digest()

        full_ciphertext = tag + cipher.nonce + ciphertext 

        return full_ciphertext

    def unprotect_message(self, data, counter, aes, hmac):
        tag = data[:32]
        nonce = data[32:40]
        ciphertext = data[40:]

        try:
            hmac = HMAC.new(hmac, digestmod=SHA256)
            tag = hmac.update(nonce + ciphertext).verify(tag)
        except ValueError:
            self.log("The message was modified!", "ERROR")
            sys.exit(1)

        cipher = AES.new(aes, AES.MODE_CTR, nonce=nonce)
                
        decrypt = cipher.decrypt(ciphertext)
        counter_received_bin = decrypt[:4]
        message = decrypt[4:]

        counter_received = int.from_bytes(counter_received_bin, byteorder='little')
        if (counter != counter_received) :
            self.log("Replay attack detected", "ERROR")
            sys.exit(1)

        return message

################################################################################

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="Run as server")
    parser.add_argument("--client", action="store_true", help="Run as client")
    parser.add_argument("--debug-level", type=int, choices=[0, 1, 2], default=0, help="Debug level: 0 for ERROR, 1 for WARNING, 2 for INFO/DEBUG.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Hostname to bind/connect to")
    parser.add_argument("--port", type=int, default=65432, help="Port to bind/connect to")

    args = parser.parse_args()

    if args.server:
        role = 'server'
    elif args.client:
        role = 'client'
    else:
        print("\033[91m[ERROR] Please specify either --server or --client\033[0m")
        sys.exit(1)

    app = SecureCommunicationApp(role, host=args.host, port=args.port, debug_level=args.debug_level)
    app.start()


if __name__ == "__main__":
    main()
