from random import randrange
class Diffie:
	p =  77194725692692818585312976243313126356125088053576198019167037
	658708802679026454975705406979662129533523436955653591928289619016
	756883208903215422762259864933635930368849770408247757361844465532
	617737385309375779589521271342917082191914881045604614868709351067
	1093321870910721288966157817696783331467
	
	g = 2
	
	def losujSecret(self, p, imie):
		print("\nGenerowanie sekretu dla " + imie)
		privateKey = randrange(2, p - 2)
		print("Wygenerowano privateKey o wartosci: ", privateKey)
		return privateKey
		
	def obliczKluczPubliczny(self, p, g, privateKey, imie):
		print("Ustalanie klucza publicznego dla " + imie)
		publicKey = pow(g, privateKey, p)
		print("Wygenerowano publicKey o wartosci: ", publicKey)
		return publicKey
		
	def obliczKluczSesji(self, publicKey, secret, p, imie):
		print("Generacja klucza sesyjnego dla " + imie)
		sessionKey = pow(publicKey, secret, p)
		print("Wygenerowano klucz sesyjny o wartosci: ", sessionKey)
		return sessionKey
	




	