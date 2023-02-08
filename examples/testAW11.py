from cryptography import *

def run_aw11():
    scheme = ABE(scheme=Aw11, attributes=["A", "B"], policy='"A" or "B"')
    scheme.generate_static_keys()
    scheme.keygen("bob", ["A"])
    ciphertext = scheme.encrypt("our plaintext!")
    plaintext_after = scheme.decrypt(ciphertext)
    print("".join(chr(i) for i in plaintext_after))

run_aw11()

