from zksk import Secret, DLRep
from zksk import utils


def ZK_equality(G, H):
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))
    m = Secret(utils.get_random_num(bits=128))

    # Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    C1 = r1.value * G
    C2 = r1.value * H + m.value * G

    D1 = r2.value * G
    D2 = r2.value * H + m.value * G

    # Generate a NIZK proving equality of the plaintexts
    zk_proof = DLRep(C1, r1.value * G) & DLRep(C2, r1.value * H + m.value * G) & DLRep(D1, r2.value * G) & \
               DLRep(D2, r2.value * H + m.value * G)

    # Return two ciphertexts and the proof
    return (C1, C2), (D1, D2), zk_proof
