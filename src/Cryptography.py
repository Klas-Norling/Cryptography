from rabe_py import aw11
from rabe_py import ac17

class ABEscheme:
    public_key = None
    master_secret_key = None
    

class ABE:
    def __init__(scheme:ABEscheme, attributes:list[str], policy:str):
        match scheme:
            case Aw11:
                aw11 = Aw11(attributes, policy)
            case Ac17:
                ac17 = Ac17(attributes, policy)
        pass



class Aw11(ABEscheme):
    def __init__(self, attributes, policy):
        self.attributes = attributes
        self.policy = policy 

    def encrypt(plaintext:str, attributes:list[str], policy:str):
        gk = aw11.setup()
        (pk, msk) = aw11.authgen(gk, attributes)
        ciphertext = aw11.encrypt(gk, pk, policy, plaintext)
        return gk, ciphertext, msk
        
        

class Ac17(ABEscheme):
    def __init__(self, global_key:str, secret_key:str):
        pass





