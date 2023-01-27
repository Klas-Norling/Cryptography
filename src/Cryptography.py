from typing import Type
from rabe_py import aw11
from rabe_py import ac17

class ABEscheme:
    def encrypt(self, plaintext:str) -> None:
        pass

    def decrypt(self, ciphertext:str) -> str:
        pass
    

class ABE:
    def __init__(scheme:Type, attributes:list[str], policy:str):
        if type(scheme) != Type:
            return "Scheme has to be either ac17 or aw11"
        if scheme == Aw11:
            aw11 = Aw11(attributes, policy)
        if scheme == Ac17:
            ac17 = Ac17(attributes, policy)



class Aw11(ABEscheme):
    def __init__(self, attributes, policy):
        self.attributes = attributes
        self.policy = policy 

    def encrypt(self, plaintext:str):
        gk = aw11.setup()
        #Save to target storage
        (pk, msk) = aw11.authgen(gk, self.attributes)
        ciphertext = aw11.encrypt(gk, pk, self.policy, plaintext)
        return gk, ciphertext, msk
    
    def decrypt(gk, ciphertext, msk, user_name:str, user_attribute:list[str]):
        sk = aw11.keygen(gk, msk, user_name, user_attribute)
        plaintext = aw11.decrypt(gk, sk, ciphertext)
        return plaintext
    
    def keygen(self):
        gk = aw11.setup()
        (pk, msk) = aw11.authgen(gk, self.attributes)
        return gk, pk, msk
        

class Ac17(ABEscheme):
    def __init__(self, attributes, policy):
        self.attributes = attributes
        self.policy = policy





