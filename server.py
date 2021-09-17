import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from hashlib import md5
from base64 import b64encode


class AESCipher:
    def __init__(self, key):
        self.key = md5(key).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'),
                                                      AES.block_size)))


###########################################################
path_to_keys = '/Users/safiullint.t./Desktop/KBRS_2/keys/'
sock = socket.socket()
sock.bind(('127.0.0.1', 9090))
sock.listen(10)
file = open(path_to_keys + "receiver.pem", "wb")

conn, addr = sock.accept()
msg = "|---------------------------------|**Welcome to Server**|---------------------------------|"
conn.send(msg.encode())
RecvData = conn.recv(1024)
while RecvData:
    file.write(RecvData)
    RecvData = conn.recv(1024)
file.close()
print("\n File has been copied successfully \n")
conn.close()

session_key = get_random_bytes(16)
recipient_key = RSA.import_key(open("/Users/safiullint.t./Desktop/KBRS_2/keys/receiver.pem").read())

cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

conn, addr = sock.accept()
conn.send(enc_session_key)
conn.close()

n = 50
while n != 0:
    conn, addr = sock.accept()
    filename = conn.recv(50).decode('utf-8')
    conn.close()
    path_to_file = '/Users/safiullint.t./Desktop/KBRS_2/files/'

    conn, addr = sock.accept()
    conn.send(AESCipher(session_key).encrypt(open(path_to_file + filename).read()))
    conn.close()
