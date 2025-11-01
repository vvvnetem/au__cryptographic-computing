/**
 * Bob: homomorphic evaluator for blood compatibility using DHE.add and DHE.multiply.
 *
 * Evaluates compatibility bit for donor and recipient, returning a ciphertext.
 */
public class Bob {

    /**
     * Evaluate compatibility:
     * - donor bits are plaintext ints (0 or 1)
     * - payload contains encrypted recipient bits
     * Returns encrypted 0/1 (DHE.Ciphertext) under Alice's public key
     */
    public DHE.Ciphertext evaluateCompatibility(
            int donorRh, int donorB, int donorA,
            Alice.RecipientPayload payload,
            DHE.PublicKey pub,
            DHE.PrivateKey privateKey) {

        DHE.Ciphertext rRh = payload.encRh; // recipient Rh
        DHE.Ciphertext rB  = payload.encB;  // recipient B
        DHE.Ciphertext rA  = payload.encA;  // recipient A

        // Encrypt 1 and 0 locally for convenience
        DHE.Ciphertext encOne  = DHE.encryptBit(1, pub, new java.security.SecureRandom(), Math.max(1, pub.n/16));
        DHE.Ciphertext encZero = DHE.encryptBit(0, pub, new java.security.SecureRandom(), Math.max(1, pub.n/16));

        DHE.Ciphertext aboSum;

        // ABO compatibility branch
        if (donorA == 0 && donorB == 0) { // O donor: universal
            aboSum = encOne;
        } else if (donorA == 1 && donorB == 0) { // A donor
            DHE.Ciphertext rAandB = DHE.multiply(rA, rB, pub, privateKey); // rA AND rB (recipient AB)
            // OR(a,b) = a + b + a*b
            DHE.Ciphertext aPlusb = DHE.add(rA, rAandB, pub);
            DHE.Ciphertext aOrb = DHE.add(aPlusb, DHE.multiply(rA, rAandB, pub, privateKey), pub);
            aboSum = aOrb;
        } else if (donorA == 0 && donorB == 1) { // B donor
            DHE.Ciphertext rAandB = DHE.multiply(rA, rB, pub, privateKey); // rA AND rB (recipient AB)
            DHE.Ciphertext bPlusAB = DHE.add(rB, rAandB, pub);
            DHE.Ciphertext bOrb = DHE.add(bPlusAB, DHE.multiply(rB, rAandB, pub, privateKey), pub);
            aboSum = bOrb;
        } else { // AB donor
            aboSum = DHE.multiply(rA, rB, pub, privateKey); // rA AND rB
        }

        // Rh compatibility: donorRh == 0 -> universal, else recipient must match
        DHE.Ciphertext rhCompat = (donorRh == 0) ? encOne : rRh;

        // Final compatibility: ABO AND Rh
        return DHE.multiply(aboSum, rhCompat, pub, privateKey);
    }
}
