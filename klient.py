#klient.py
from diffie import *
import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

s = socket.socket()
host = socket.gethostname()
port = int(input("Wprowadz port na którym chcesz się połączyć z serwerem: "))

#utworzenie obiektu klient typu Diffie
klient = Diffie()

#wygenerowanie private key dla klienta
klientPrivateKey = klient.losujSecret(klient.p, "Klienta")

#wygenerowanie public key dla klienta
klientPublicKey = str(klient.obliczKluczPubliczny(klient.p, klient.g, klientPrivateKey, "Klienta"))

#nawiązanie połączenia z serwerem
s.connect((host, port))

#przeslanie publicKey
print("Przeslano PublicKey do Serwera", klientPublicKey)
s.send(klientPublicKey.encode("utf-8"))

#odebranie foreignKey
foreignKey = int(s.recv(1024).decode("utf-8"))
print("Odebrano klucz publiczny od Klienta: ", foreignKey)
sessionKey = str(klient.obliczKluczSesji(foreignKey, klientPrivateKey, klient.p, "Klienta"))
print("Obliczony klucz sesji dla klienta to: ", sessionKey)


#hashowanie 
hash = SHA256.new()
hash.update(sessionKey.encode("utf-8"))

#AES
aes = AES.new(hash.digest(), AES.MODE_ECB)

#zaszyfrowanie wiadomosci nr 1
m = input("podaj wiadomość: ")
length = len(m) % 16
j = 0
for j in range (16 - length):
	m = m + " "
print("Szyfrowanie...")
ct = aes.encrypt(m.encode("utf-8"))


#wysłanie szyfrogramu nr 1
print("Przeslanie szyfrogramu do serwera: ", ct)
s.send(ct)

#odebranie wiadomosci nr 1
ct = s.recv(1024)
print("Odebranie szyfrogramu od serwera.", ct)

#dekodowanie nr 1
print("Dekodowaie...")
pt = aes.decrypt(ct)
print("Wiadomosc od serwera: ",pt)

m = input("podaj wiadomość: ")
length = len(m) % 16
j = 0
for j in range (16 - length):
	m = m + " "

#zaszyfrowanie wiadomosci nr 2
print("Szyfrowanie...")
ct = aes.encrypt(m.encode("utf-8"))


#wysłanie szyfrogramu nr 2
print("Przeslanie szyfrogramu do serwera: ", ct)
s.send(ct)


#odebranie wiadomosci nr 2
ct = s.recv(1024)
print("Odebranie szyfrogramu od serwera", ct)

#dekodowanie nr 2
print("Dekodowaie...")
pt = aes.decrypt(ct)
print("Wiadomosc od serwera: ",pt)



s.close()
