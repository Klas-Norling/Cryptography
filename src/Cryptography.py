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
            return aw11
        if scheme == KPAc17:
            ac17 = KPAc17(attributes, policy)
            return ac17



class Aw11(ABEscheme):
    def __init__(self, attributes:list[str], policy:str):
        self.attributes = attributes
        self.policy = policy 
        self.gk = None
        self.pk = None
        self.msk = None
        self.sk = None

    def encrypt(self, plaintext:str):
        #Save to target storage
        ciphertext = aw11.encrypt(self.gk, self.pk, self.policy, plaintext)
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = aw11.decrypt(self.gk, self.sk, ciphertext)
        return plaintext
    
    def keygen(self, user_name:str, user_attribute:list[str]):
        gk = aw11.setup()
        (pk, msk) = aw11.authgen(gk, self.attributes)
        sk = aw11.keygen(gk, msk, user_name, user_attribute)
        self.gk = gk
        self.pk = pk
        self.sk = sk
        

class KPAc17(ABEscheme):
    def __init__(self, attributes:list[str], policy:str):
        self.attributes = attributes
        self.policy = policy
        self.pk = None
        self.msk = None
        self.sk = None

    def encrypt(self, plaintext:str):
        ciphertext = ac17.kp_encrypt(self.pk, self.attributes, plaintext)
        return ciphertext

    def decrypt(self, ciphertext:str):
        plaintext = ac17.kp_decrypt(self.sk, ciphertext)
        return plaintext

    def keygen(self):
        (pk, msk) = ac17.setup()
        sk = ac17.kp_keygen(msk, self.policy)
        self.pk = pk
        self.msk = msk
        self.sk = sk
    

class CPAc17(ABEscheme):
    def __init__(self, attributes:list[str], policy:str):
        self.attributes = attributes
        self.policy = policy
        self.pk = None
        self.msk = None
        self.sk = None
    
    def encrypt(self, plaintext:str):
        ciphertext = ac17.cp_encrypt(self.pk, self.policy, plaintext)
        return ciphertext

    def decrypt(self, ciphertext:str):
        plaintext = ac17.cp_decrypt(self.sk, ciphertext)
        return plaintext

    def keygen(self):
        (pk, msk) = ac17.setup()
        sk = ac17.cp_keygen(msk, self.attributes)
        self.pk = pk
        self.msk = msk
        self.sk = sk





