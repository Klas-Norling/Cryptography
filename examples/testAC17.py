from cryptography import *


def run_kpac17():
    scheme = ABE(scheme=KPAc17, attributes=["A", "B"], policy='("A" and "B")')
    scheme.generate_static_keys()
    scheme.keygen()
    ciphertext = scheme.encrypt("Secret")
    plaintext_after = scheme.decrypt(ciphertext)
    print(plaintext_after)


def run_cpac17():
    scheme = ABE(scheme=CPAc17, attributes=["A", "B"], policy='("A" and "B")')
    scheme.generate_static_keys()
    scheme.keygen()
    ciphertext = scheme.encrypt("Secret 2")
    plaintext_after = scheme.decrypt(ciphertext)
    print(plaintext_after)

run_kpac17()
run_cpac17()