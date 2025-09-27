package org.example;

import java.math.BigInteger;

public class Alice {
    ElGamal.SecretKey secretKey;
    int bloodType;
    ElGamal elGamal;

    public Alice(int bloodType, ElGamal elGamal) {
        this.bloodType = bloodType;
        this.elGamal = elGamal;
    }

    public ElGamal.PublicKey[] createPublicKeys() {

        ElGamal.PublicKey[] publicKeys = new ElGamal.PublicKey[8];
        ElGamal.KeyPair keyPair = elGamal.generateKeyPair();
        secretKey = keyPair.secretKey;
        publicKeys[bloodType] = keyPair.publicKey;


        for (int i = 0; i < 8; i++) {
            if (i != bloodType) {
                publicKeys[i] = elGamal.oGen();
            }
        }
        return publicKeys;
    }

    public BigInteger retrieveResult(ElGamal.Ciphertext[] ciphertexts) {
        return elGamal.decrypt(ciphertexts[bloodType], secretKey);
    }
}
