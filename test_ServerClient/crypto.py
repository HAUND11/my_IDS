import rsa

class Crypto():

    def __init__(self):
        (self.pubkey, self.privkey) = rsa.newkeys(1024, accurate=True, poolsize=1)

    def init_keys(self):
         return self.pubkey

    # def encrypted(self, encrypted_data):
    #     return rsa.encrypt(encrypted_data, self.pubkey)

    def decrypted(self,decrypted_data):
        return rsa.decrypt(decrypted_data, self.privkey)
