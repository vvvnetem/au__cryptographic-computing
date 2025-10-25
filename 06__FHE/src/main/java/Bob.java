/**
 * Bob: receives encrypted recipient payload from Alice and uses his plaintext donor bits
 * to compute compatibility using only Paillier homomorphic operations and public key.
 *
 * Policy:
 * - donor bits are provided as integers (0 or 1).
 * - Uses payload fields prepared by Alice (encrypted masks).
 */
public class Bob {

    /**
     * Evaluate compatibility homomorphically.
     *
     * donorRh, donorB, donorA are plaintext ints (0 or 1).
     * recipientPayload contains the encrypted recipient masks prepared by Alice.
     *
     * Returns an encrypted single-bit ciphertext (0/1) under Alice's public key.
     */
    public Paillier.Ciphertext evaluateCompatibility(
            int donorRh, int donorB, int donorA,
            Alice.RecipientPayload payload,
            Paillier.PublicKey pub) {

        // Determine donor ABO type indicators (exactly one equals 1)
        int isO  = ((donorA == 0) && (donorB == 0)) ? 1 : 0;
        int isA  = ((donorA == 1) && (donorB == 0)) ? 1 : 0;
        int isB  = ((donorA == 0) && (donorB == 1)) ? 1 : 0;
        int isAB = ((donorA == 1) && (donorB == 1)) ? 1 : 0;

        // ABO options (encrypted):
        // encOne, encA, encB, encAB correspond to type O, A, B, AB respectively
        // ABO_selected = sum_{type} indicator * option
        Paillier.Ciphertext termO = (isO == 1) ? payload.encOne : payload.encZero;
        Paillier.Ciphertext termA = (isA == 1) ? payload.encA : payload.encZero;
        Paillier.Ciphertext termB = (isB == 1) ? payload.encB : payload.encZero;
        Paillier.Ciphertext termAB= (isAB== 1) ? payload.encAB: payload.encZero;

        // Sum them (homomorphic addition)
        Paillier.Ciphertext ABO_selected = Paillier.add(
                Paillier.add(termO, termA, pub),
                Paillier.add(termB, termAB, pub),
                pub);

        // ABO_with_rh options: precomputed by Alice: encRh, encA_rh, encB_rh, encAB_rh
        Paillier.Ciphertext troO = (isO == 1) ? payload.encRh : payload.encZero;
        Paillier.Ciphertext troA = (isA == 1) ? payload.encA_rh : payload.encZero;
        Paillier.Ciphertext troB = (isB == 1) ? payload.encB_rh : payload.encZero;
        Paillier.Ciphertext troAB= (isAB== 1) ? payload.encAB_rh: payload.encZero;

        Paillier.Ciphertext ABO_with_rh = Paillier.add(
                Paillier.add(troO, troA, pub),
                Paillier.add(troB, troAB, pub),
                pub);

        // Now select based on donorRh:
        // final = (1 - donorRh) * ABO_selected + donorRh * ABO_with_rh
        // We can implement multiplication by 0/1 by either selecting encZero/enc or scalarMul with 0/1.
        Paillier.Ciphertext part1 = (donorRh == 0) ? ABO_selected : payload.encZero; // (1-donorRh)==1 -> ABO_selected
        Paillier.Ciphertext part2 = (donorRh == 1) ? ABO_with_rh : payload.encZero;

        Paillier.Ciphertext finalCt = Paillier.add(part1, part2, pub);
        return finalCt;
    }
}
