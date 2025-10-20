package org.example;

import java.math.BigInteger;

public class Bob {
    int bloodType;
    ElGamal elGamal;

    public Bob(int bloodType, ElGamal elGamal) {
        this.bloodType = bloodType;
        this.elGamal = elGamal;
    }

    public ElGamal.Ciphertext[] encryptBloodType(ElGamal.PublicKey[] publicKeys) {
        BigInteger[] compatibilityMessages = new BigInteger[8];
        for (int i = 0; i < 8; i++) {
            // Compatibility: can Alice (if she had blood type i) receive from Bob?
            compatibilityMessages[i] = BigInteger.valueOf(Main.COMPATIBILITY_MATRIX[i][bloodType]);
        }

        ElGamal.Ciphertext[] ciphertexts = new ElGamal.Ciphertext[8];
        for (int i = 0; i < 8; i++) {
            ciphertexts[i] = elGamal.encrypt(compatibilityMessages[i], publicKeys[i]);
        }
        return ciphertexts;
    }
}
