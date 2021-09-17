import os
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
import sqlite3
from PyQt5 import QtWidgets
from Crypto.PublicKey import RSA
import socket
import kbrs
from hashlib import md5
from base64 import b64decode
from Crypto.Util.Padding import unpad
import window_sign_in
import window_create_acc


conn = sqlite3.connect('example.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS account (username TEXT, password TEXT)''')
c.execute('''INSERT INTO account (username, password) VALUES ('Username', 'Password')''')
c.execute('''SELECT * FROM account''')
p = c.fetchall()
print(p)

class AESCipher:
    def __init__(self, key):
        self.key = md5(key).digest()

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)

class FirstClass(QtWidgets.QMainWindow, window_sign_in.Ui_MainWindow):
    def __init__(self, parent=None):
        super(FirstClass, self).__init__(parent)
        self.setupUi(self)
        self.window_create_acc = None
        self.main_window = None

        self.pushButton.clicked.connect(self.sign_in)

    def sign_in(self):
        s = '%' + self.lineEdit.text() + '%'
        s1 = '%' + self.lineEdit_2.text() + '%'
        c.execute('''SELECT * FROM account WHERE username LIKE ? AND password LIKE ?''', (s, s1))
        s2 = c.fetchall()
        if not s2:
            self.show_window_create_acc()
        else:
            self.close()
            self.show_main_window()

    def show_window_create_acc(self):
        self.window_create_acc = SecondClass()
        self.window_create_acc.show()

    def show_main_window(self):
        self.main_window = ThirdClass()
        self.main_window.show()


class SecondClass(QtWidgets.QMainWindow, window_create_acc.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.pushButton.clicked.connect(self.add_note)

    def add_note(self):
        s1 = self.lineEdit.text()
        s2 = self.lineEdit_2.text()
        c.execute('''INSERT INTO account (username,password) VALUES (?,?)''', (s1, s2))
        c.execute('''SELECT * FROM account''')
        print(c.fetchall())
        self.close()

class ThirdClass(QtWidgets.QMainWindow, kbrs.Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)

        self.pushButton_2.clicked.connect(self.generate_keys)
        self.pushButton.clicked.connect(self.send_pub_key)
        self.listWidget.addItems(os.listdir('/Users/safiullint.t./Desktop/KBRS_2/files'))
        self.enc_session_key = b''
        self.pushButton_3.clicked.connect(self.decr_and_show_text)

    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        self.pushButton_2.setEnabled(False)

    def send_pub_key(self):
        sock = socket.socket()
        sock.connect(('127.0.0.1', 9090))
        file = open("receiver.pem", "rb")
        SendData = file.read(1024)

        while SendData:
            print("\n\n################## Below message is received from server ################## \n\n ",
                  sock.recv(1024))
            sock.send(SendData)
            SendData = file.read(1024)
        self.pushButton.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        sock.close()
        sock = socket.socket()
        sock.connect(('127.0.0.1', 9090))
        self.enc_session_key = sock.recv(1024)
        sock.close()

    def decr_and_show_text(self):
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(open("private.pem").read()))
        session_key = cipher_rsa.decrypt(self.enc_session_key)
        n = 50
        while n != 0:
            sock = socket.socket()
            sock.connect(('127.0.0.1', 9090))
            sock.send(self.lineEdit.text().encode('utf-8'))
            sock.close()
        #########################
            sock = socket.socket()
            sock.connect(('127.0.0.1', 9090))
            text = sock.recv(5000)
            sock.close()
            self.textBrowser.setText(AESCipher(session_key).decrypt(text).decode('utf-8'))
            n -= 1


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = FirstClass()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
