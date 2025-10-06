package org.example;

import java.security.MessageDigest;

/**
 * Alice is the circuit evaluator in Yao's Garbled Circuit protocol.
 * She receives the garbled circuit from Bob and evaluates it using her input labels.
 * Alice learns only the final output without learning Bob's input or the circuit's intermediate values.
 */
class Alice {
    private MessageDigest sha256;

    public Alice() throws Exception {
        sha256 = MessageDigest.getInstance("SHA-256");
    }

    /**
     * Evaluate the garbled circuit to compute the final result.
     * Alice has wire labels for all inputs but doesn't know what values they represent.
     * She evaluates gates one by one, propagating wire labels through the circuit.
     *
     * @param garbledCircuit Array of garbled gates (encrypted truth tables)
     * @param aliceInputLabels Wire labels for Alice's 3 input bits (obtained via OT)
     * @param bobInputLabels Wire labels for Bob's 3 input bits (received directly)
     * @param outputDecoding Mapping to decode the final wire label to true/false
     * @return The computed result (blood compatibility: true = compatible, false = not compatible)
     */
    public boolean evaluateCircuit(GarbledGate[] garbledCircuit,
                                   WireLabel[] aliceInputLabels,
                                   WireLabel[] bobInputLabels,
                                   WireLabel[] outputDecoding) {

        // Store all wire labels as we compute them
        // Wires 0-5 are inputs, wires 6-13 are computed from gates
        WireLabel[] wireValues = new WireLabel[14];

        // Set input wire labels
        // Wires 0-2: Alice's input (xA, xB, xR) - her blood type
        // Wires 3-5: Bob's input (yA, yB, yR) - his blood type
        for (int i = 0; i < 3; i++) {
            wireValues[i] = aliceInputLabels[i].copy();
            wireValues[3 + i] = bobInputLabels[i].copy();
        }

        // Evaluate gates in topological order (inputs to outputs)
        // Each gate evaluation finds the correct entry to decrypt
        int gateIndex = 0;

        // NOT gates (wires 6, 7, 8): Negate Bob's inputs
        // Wire 6 = ~yA, Wire 7 = ~yB, Wire 8 = ~yR
        wireValues[6] = evaluateUnaryGate(garbledCircuit[gateIndex++], wireValues[3], 6);
        wireValues[7] = evaluateUnaryGate(garbledCircuit[gateIndex++], wireValues[4], 7);
        wireValues[8] = evaluateUnaryGate(garbledCircuit[gateIndex++], wireValues[5], 8);

        // OR gates (wires 9, 10, 11): Check compatibility for each antigen
        // Wire 9 = xA | ~yA (recipient has A or donor doesn't)
        // Wire 10 = xB | ~yB (recipient has B or donor doesn't)
        // Wire 11 = xR | ~yR (recipient has Rh+ or donor doesn't)
        wireValues[9] = evaluateBinaryGate(garbledCircuit[gateIndex++], wireValues[0], wireValues[6], 9);
        wireValues[10] = evaluateBinaryGate(garbledCircuit[gateIndex++], wireValues[1], wireValues[7], 10);
        wireValues[11] = evaluateBinaryGate(garbledCircuit[gateIndex++], wireValues[2], wireValues[8], 11);

        // AND gates (wires 12, 13): Combine all compatibility conditions
        // Wire 12 = (xA|~yA) & (xB|~yB)
        // Wire 13 = (xA|~yA) & (xB|~yB) & (xR|~yR) - final result
        wireValues[12] = evaluateBinaryGate(garbledCircuit[gateIndex++], wireValues[9], wireValues[10], 12);
        wireValues[13] = evaluateBinaryGate(garbledCircuit[gateIndex++], wireValues[12], wireValues[11], 13);

        // Decode output: compare final wire label to the decoding map
        // Alice checks which label she got and translates it to true/false
        if (wireValues[13].equals(outputDecoding[0])) {
            return false;  // Blood types not compatible
        } else if (wireValues[13].equals(outputDecoding[1])) {
            return true;   // Blood types compatible
        } else {
            throw new RuntimeException("Invalid output label!");
        }
    }

    /**
     * Evaluate a unary gate (NOT gate) by trying to decrypt all entries.
     * Alice tries all 4 encrypted entries and finds the one that decrypts successfully.
     *
     * @param gate The garbled gate with 4 encrypted entries
     * @param input The input wire label
     * @param gateId The gate identifier (output wire number)
     * @return The decrypted output wire label
     */
    private WireLabel evaluateUnaryGate(GarbledGate gate, WireLabel input, int gateId) {
        // Try all 4 entries (2 real + 2 dummy, randomly shuffled)
        // Only one will decrypt successfully with the correct verification tag
        for (int i = 0; i < 4; i++) {
            WireLabel decrypted = tryDecrypt(input, null, gate.ciphertexts[i], gateId);
            if (decrypted != null) {
                return decrypted;  // Found the correct entry!
            }
        }
        throw new RuntimeException("Could not evaluate unary gate " + gateId);
    }

    /**
     * Evaluate a binary gate (AND/OR gate) by trying to decrypt all entries.
     * Alice tries all 4 encrypted entries and finds the one matching her input labels.
     *
     * @param gate The garbled gate with 4 encrypted entries
     * @param left The left input wire label
     * @param right The right input wire label
     * @param gateId The gate identifier (output wire number)
     * @return The decrypted output wire label
     */
    private WireLabel evaluateBinaryGate(GarbledGate gate, WireLabel left, WireLabel right, int gateId) {
        // Try all 4 entries (one for each input combination: 00, 01, 10, 11)
        // Only the entry encrypted with Alice's actual input labels will decrypt successfully
        for (int i = 0; i < 4; i++) {
            WireLabel decrypted = tryDecrypt(left, right, gate.ciphertexts[i], gateId);
            if (decrypted != null) {
                return decrypted;  // Found the correct entry!
            }
        }
        throw new RuntimeException("Could not evaluate binary gate " + gateId);
    }

    /**
     * Attempt to decrypt a garbled gate entry and verify the authentication tag.
     *
     * Decryption process:
     * 1. Compute PRF using Alice's input wire labels
     * 2. XOR the PRF with the ciphertext to get the output label
     * 3. Check the verification tag - should be all zeros if decryption is correct
     *
     * @param left Left input wire label (decryption key)
     * @param right Right input wire label (null for unary gates)
     * @param ciphertext Encrypted entry: [encrypted_label (4 ints) | verification_tag (4 ints)]
     * @param gateId Gate identifier to compute unique PRF per gate
     * @return The decrypted wire label if successful, null if tag verification fails
     */
    private WireLabel tryDecrypt(WireLabel left, WireLabel right, int[] ciphertext, int gateId) {
        // Compute the same PRF that Bob used for encryption
        // This only works if Alice has the correct input labels
        int[] prf = computePRF(left, right, gateId);

        // Decrypt the output label: plaintext = ciphertext ⊕ PRF
        // This reverses Bob's encryption: ciphertext = plaintext ⊕ PRF
        WireLabel result = new WireLabel();
        for (int i = 0; i < 4; i++) {
            result.key[i] = prf[i] ^ ciphertext[i];
        }

        // Check the verification tag (should be all zeros when correct)
        // Bob encrypted 0 with the last 4 ints of PRF
        // If we decrypt and get 0, we know this is the right entry
        boolean tagValid = true;
        for (int i = 0; i < 4; i++) {
            int decryptedTag = prf[i + 4] ^ ciphertext[i + 4];
            if (decryptedTag != 0) {
                tagValid = false;
                break;
            }
        }

        // Return the decrypted label only if the tag is valid
        // Otherwise return null to indicate this entry doesn't match Alice's inputs
        return tagValid ? result : null;
    }

    /**
     * Compute a Pseudo-Random Function (PRF) using SHA-256.
     * This is identical to Bob's computePRF method.
     *
     * Alice computes PRF(her_labels, gateId) and compares it with Bob's
     * encrypted entries. Only when Alice has the correct labels will the
     * PRF match and decryption succeed.
     *
     * @param left Left input wire label
     * @param right Right input wire label (null for unary gates)
     * @param gateId Gate identifier (output wire number)
     * @return 8 integers (256 bits) of pseudo-random data
     */
    private int[] computePRF(WireLabel left, WireLabel right, int gateId) {
        sha256.reset();

        // Hash left key: convert 4 integers to 16 bytes
        for (int i = 0; i < 4; i++) {
            sha256.update((byte) (left.key[i] >> 24));
            sha256.update((byte) (left.key[i] >> 16));
            sha256.update((byte) (left.key[i] >> 8));
            sha256.update((byte) left.key[i]);
        }

        // Hash right key if present (for binary gates)
        if (right != null) {
            for (int i = 0; i < 4; i++) {
                sha256.update((byte) (right.key[i] >> 24));
                sha256.update((byte) (right.key[i] >> 16));
                sha256.update((byte) (right.key[i] >> 8));
                sha256.update((byte) right.key[i]);
            }
        }

        // Hash gate ID for unique encryption per gate
        sha256.update((byte) (gateId >> 24));
        sha256.update((byte) (gateId >> 16));
        sha256.update((byte) (gateId >> 8));
        sha256.update((byte) gateId);

        // Compute SHA-256 hash (32 bytes = 256 bits)
        byte[] hash = sha256.digest();

        // Convert 32 bytes to 8 integers
        int[] result = new int[8];
        for (int i = 0; i < 8; i++) {
            result[i] = ((hash[i * 4] & 0xFF) << 24) |
                    ((hash[i * 4 + 1] & 0xFF) << 16) |
                    ((hash[i * 4 + 2] & 0xFF) << 8) |
                    (hash[i * 4 + 3] & 0xFF);
        }

        return result;
    }
}
