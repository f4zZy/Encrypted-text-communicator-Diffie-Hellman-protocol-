# serwer.py
import socket
from diffie import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
#sockety
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = socket.gethostname()
port = int(input("Wprowadz port na którym chcesz się połączyć z klientem: "))

#utworzenie obiektu serwera typu Diffie
serwer = Diffie()

#wygenerowanie private key dla serwera
serwerPrivateKey = serwer.losujSecret(serwer.p, "Serwera")

#wygenerowanie public key dla serwera
serwerPublicKey = str(serwer.obliczKluczPubliczny(serwer.p, serwer.g, serwerPrivateKey, "Serwera"))


s.bind((host, port))
s.listen(5)
print("Oczekiwanie na polaczenie")
c, addr = s.accept()
print("Polaczono: ", addr)


#wyslanie publicKey
c.send(serwerPublicKey.encode("utf-8"))
print("Przeslano PublicKey do klienta", serwerPublicKey)

#odebranie foreignKey
foreignKey = int(c.recv(1024).decode("utf-8"))
print("Odebrano klucz publiczny od Klienta: ", foreignKey)


sessionKey = str(serwer.obliczKluczSesji(foreignKey, serwerPrivateKey, serwer.p, "Serwera"))
print("Obliczony klucz sesji dla Serwera to: ", sessionKey)

#hashowanie
hash = SHA256.new()
hash.update(sessionKey.encode("utf-8"))


#AES
aes = AES.new(hash.digest(), AES.MODE_ECB)

#odebranie wiadomosci nr 1
ct = c.recv(1024)
print("Odebrano szyfrogram od klienta: ",ct)

#dekodowanie nr 1
pt = aes.decrypt(ct)
print("Dekodowanie...")
print("Wiadomosc od klienta: ",pt)


#zakodowanie wiadomosci nr 1
m = input("podaj wiadomość: ")
length = len(m) % 16
j = 0
for j in range (16 - length):
	m = m + " "
print("Szyfrowanie...")
ct = aes.encrypt(m.encode("utf-8"))

#wyslanie wiadomosci nr 1
print("Przeslanie szyfrogramu do klienta: ", ct)
c.send(ct)


#odebranie wiadomosci nr 2
ct = c.recv(1024)
print("Odebrano szyfrogram od klienta: ",ct)

#dekodowanie nr 2
pt = aes.decrypt(ct)
print("Dekodowanie...")
print("Wiadomosc od klienta: ",pt)


#zakodowanie wiadomosci nr 2
m = input("podaj wiadomość: ")
length = len(m) % 16
j = 0
for j in range (16 - length):
	m = m + " "
print("Szyfrowanie...")
ct = aes.encrypt(m.encode("utf-8"))

#wyslanie wiadomosci nr 2
print("Przeslanie szyfrogramu do klienta: ", ct)
c.send(ct)


c.close()
s.close()
