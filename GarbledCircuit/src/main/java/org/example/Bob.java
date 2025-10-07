package org.example;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Bob is the circuit garbler in Yao's Garbled Circuit protocol.
 * He creates the encrypted circuit and sends it to Alice for evaluation.
 * Bob knows the circuit structure but learns nothing about Alice's input.
 */
class Bob {
    private SecureRandom random;
    private MessageDigest sha256;

    // Wire labels: [wireIndex][0/1 value]
    // Each wire has two labels: one representing 0, one representing 1
    // These labels are 128-bit random values that act as encryption keys
    private WireLabel[][] wireLabels;

    // Circuit structure for blood compatibility
    // Wires: 0-2 = Alice's input (xA, xB, xR)
    //        3-5 = Bob's input (yA, yB, yR)
    //        6-8 = NOT gates for Bob's inputs
    //        9-11 = OR gates (xA|~yA, xB|~yB, xR|~yR)
    //        12 = AND gate (first two terms)
    //        13 = AND gate (final result)
    private static final int NUM_WIRES = 14;
    private static final int NUM_INPUT_ALICE = 3;
    private static final int NUM_INPUT_BOB = 3;

    private GarbledGate[] garbledGates;
    private WireLabel[] outputDecoding; // [0] = false label, [1] = true label

    public Bob() throws Exception {
        random = new SecureRandom();
        sha256 = MessageDigest.getInstance("SHA-256");
        wireLabels = new WireLabel[NUM_WIRES][2];
        garbledGates = new GarbledGate[8]; // 3 NOT + 3 OR + 2 AND = 8 gates
    }

    /**
     * Generate the garbled circuit by creating random wire labels and
     * encrypting the truth table for each gate.
     * This is the main garbling procedure that Bob executes.
     */
    public void garbleCircuit() {
        // Step 1: Generate random wire labels
        // For each wire, create two random 128-bit labels (one for 0, one for 1)
        for (int i = 0; i < NUM_WIRES; i++) {
            for (int j = 0; j < 2; j++) {
                wireLabels[i][j] = generateRandomLabel();
            }
        }

        // Step 2: Create garbled gates
        // Each gate encrypts its truth table using the wire labels as keys
        int gateIndex = 0;

        // NOT gates for Bob's inputs (wires 6, 7, 8)
        // These invert Bob's blood type bits
        garbledGates[gateIndex++] = garbleNOTGate(3, 6);  // ~yA
        garbledGates[gateIndex++] = garbleNOTGate(4, 7);  // ~yB
        garbledGates[gateIndex++] = garbleNOTGate(5, 8);  // ~yR

        // OR gates (wires 9, 10, 11)
        // These implement the compatibility rules: recipient has antigen OR donor doesn't
        garbledGates[gateIndex++] = garbleORGate(0, 6, 9);   // xA | ~yA
        garbledGates[gateIndex++] = garbleORGate(1, 7, 10);  // xB | ~yB
        garbledGates[gateIndex++] = garbleORGate(2, 8, 11);  // xR | ~yR

        // AND gates (wires 12, 13)
        // These combine all three compatibility conditions
        garbledGates[gateIndex++] = garbleANDGate(9, 10, 12);   // (xA|~yA) & (xB|~yB)
        garbledGates[gateIndex++] = garbleANDGate(12, 11, 13);  // result & (xR|~yR)

        // Final output is wire 13
        // Store both possible output labels so Alice can decode the result
        outputDecoding = new WireLabel[2];
        outputDecoding[0] = wireLabels[13][0].copy();
        outputDecoding[1] = wireLabels[13][1].copy();
    }

    /**
     * Generate a random 128-bit wire label.
     * Wire labels serve as encryption keys in the garbled circuit.
     */
    private WireLabel generateRandomLabel() {
        WireLabel label = new WireLabel();
        for (int i = 0; i < 4; i++) {
            label.key[i] = random.nextInt();
        }
        return label;
    }

    /**
     * Garble a NOT gate by encrypting its truth table.
     * A NOT gate has 2 real entries (0→1, 1→0) plus 2 dummy entries for security.
     *
     * @param inputWire The input wire index
     * @param outputWire The output wire index
     * @return The garbled gate with shuffled encrypted entries
     */
    private GarbledGate garbleNOTGate(int inputWire, int outputWire) {
        GarbledGate gate = new GarbledGate();

        // Create entries for both input values (and 2 dummy entries)
        // Each entry is 8 integers: 4 for encrypted label + 4 for verification tag
        int[][] entries = new int[4][8];

        // Real entries: NOT gate truth table
        // Input 0 → Output 1, Input 1 → Output 0
        for (int a = 0; a < 2; a++) {
            int outputValue = 1 - a; // NOT operation
            // Encrypt the output label using the input label as the key
            entries[a] = encryptLabel(
                    wireLabels[inputWire][a],
                    null,  // No second input for unary gate
                    wireLabels[outputWire][outputValue],
                    outputWire
            );
        }

        // Dummy entries (will never decrypt correctly)
        // These hide which entries are real, preventing information leakage
        for (int i = 2; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                entries[i][j] = random.nextInt();
            }
        }

        // Shuffle all entries so Alice can't tell which is which
        // She'll try all 4 and only one will decrypt successfully
        shuffleArray(entries);
        gate.ciphertexts = entries;

        return gate;
    }

    // Garble an OR gate
    private GarbledGate garbleORGate(int leftWire, int rightWire, int outputWire) {
        return garbleBinaryGate(leftWire, rightWire, outputWire, true);
    }

    // Garble an AND gate
    private GarbledGate garbleANDGate(int leftWire, int rightWire, int outputWire) {
        return garbleBinaryGate(leftWire, rightWire, outputWire, false);
    }

    /**
     * Garble a binary gate (AND or OR) by encrypting all 4 entries of its truth table.
     * Each combination of input values (00, 01, 10, 11) gets encrypted.
     *
     * @param leftWire Left input wire index
     * @param rightWire Right input wire index
     * @param outputWire Output wire index
     * @param isOR True for OR gate, false for AND gate
     * @return The garbled gate with shuffled encrypted entries
     */
    private GarbledGate garbleBinaryGate(int leftWire, int rightWire, int outputWire, boolean isOR) {
        GarbledGate gate = new GarbledGate();

        // Create entries for all 4 input combinations (00, 01, 10, 11)
        int[][] entries = new int[4][8];
        int entryIndex = 0;

        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 2; b++) {
                // Compute the correct output value for this input combination
                int outputValue;
                if (isOR) {
                    outputValue = (a == 1 || b == 1) ? 1 : 0;
                } else { // AND
                    outputValue = (a == 1 && b == 1) ? 1 : 0;
                }

                // Encrypt the output label using both input labels as keys
                entries[entryIndex++] = encryptLabel(
                        wireLabels[leftWire][a],
                        wireLabels[rightWire][b],
                        wireLabels[outputWire][outputValue],
                        outputWire
                );
            }
        }

        // Random permutation hides the input-to-entry mapping
        // Alice must try all entries to find the one that decrypts correctly
        shuffleArray(entries);
        gate.ciphertexts = entries;

        return gate;
    }

    /**
     * Algorithm to randomly permute the gate entries.
     * This prevents Alice from learning which entry corresponds to which input.
     */
    private void shuffleArray(int[][] array) {
        for (int i = array.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int[] temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }

    /**
     * Encrypt an output wire label using input wire labels as encryption keys.
     * Uses a PRF (pseudo-random function) to generate a one-time pad.
     *
     * Result format: [encrypted_label (4 ints) | verification_tag (4 ints)]
     *
     * @param left Left input wire label (encryption key)
     * @param right Right input wire label (null for unary gates)
     * @param output Output wire label to encrypt
     * @param gateId Gate identifier to ensure unique encryption per gate
     * @return 8 integers: 4 encrypted label + 4 verification tag
     */
    private int[] encryptLabel(WireLabel left, WireLabel right, WireLabel output, int gateId) {
        int[] result = new int[8]; // 4 for encrypted label + 4 for encrypted tag

        // Generate 256 bits of pseudo-random data from the input labels
        int[] prf = computePRF(left, right, gateId);

        // Encrypt the output label: ciphertext = PRF ⊕ plaintext
        // First 4 ints of PRF are XORed with the output label
        for (int i = 0; i < 4; i++) {
            result[i] = prf[i] ^ output.key[i];
        }

        // Create verification tag: last 4 ints of PRF XORed with 0
        // When Alice decrypts correctly, this will yield all zeros
        // If decryption fails, this will be random garbage
        for (int i = 0; i < 4; i++) {
            result[i + 4] = prf[i + 4] ^ 0; // XOR with 0 (just copies PRF)
        }

        return result;
    }

    /**
     * Compute a Pseudo-Random Function (PRF) using SHA-256.
     * This generates deterministic but unpredictable cryptographic output.
     *
     * PRF(left, right, gateId) = SHA256(left || right || gateId)
     *
     * Properties:
     * - Deterministic: same inputs always produce same output
     * - Unpredictable: can't predict output without knowing inputs
     * - One-way: can't reverse to find inputs
     * - Unique per gate: gateId ensures different gates have different keys
     *
     * @param left Left input wire label
     * @param right Right input wire label (null for unary gates)
     * @param gateId Gate identifier (output wire number)
     * @return 8 integers (256 bits) of pseudo-random data
     */
    private int[] computePRF(WireLabel left, WireLabel right, int gateId) {
        sha256.reset();

        // Hash left key: convert 4 integers to 16 bytes
        // Each integer is broken into 4 bytes using bit shifts
        for (int i = 0; i < 4; i++) {
            sha256.update((byte) (left.key[i] >> 24));  // Most significant byte
            sha256.update((byte) (left.key[i] >> 16));  // 2nd byte
            sha256.update((byte) (left.key[i] >> 8));   // 3rd byte
            sha256.update((byte) left.key[i]);          // Least significant byte
        }

        // Hash right key if present (for binary gates)
        // For unary gates (NOT), right is null so this is skipped
        if (right != null) {
            for (int i = 0; i < 4; i++) {
                sha256.update((byte) (right.key[i] >> 24));
                sha256.update((byte) (right.key[i] >> 16));
                sha256.update((byte) (right.key[i] >> 8));
                sha256.update((byte) right.key[i]);
            }
        }

        // Hash gate ID (output wire number)
        // This ensures each gate has unique encryption even with same inputs
        // Prevents "cross-gate" attacks where Alice might try to use labels from one gate on another
        sha256.update((byte) (gateId >> 24));
        sha256.update((byte) (gateId >> 16));
        sha256.update((byte) (gateId >> 8));
        sha256.update((byte) gateId);

        // Finalize the hash: produces 32 bytes (256 bits) of output
        byte[] hash = sha256.digest();

        // Convert 32 bytes to 8 integers (4 bytes per integer)
        // Each integer combines 4 consecutive bytes using shifts and OR operations
        int[] result = new int[8];
        for (int i = 0; i < 8; i++) {
            // & 0xFF ensures byte is treated as unsigned (0-255)
            // << shifts bytes into position: byte0 goes to bits 24-31, byte1 to 16-23, etc.
            // | combines all 4 bytes into one 32-bit integer
            result[i] = ((hash[i * 4] & 0xFF) << 24) |
                    ((hash[i * 4 + 1] & 0xFF) << 16) |
                    ((hash[i * 4 + 2] & 0xFF) << 8) |
                    (hash[i * 4 + 3] & 0xFF);
        }

        return result;
    }

    // Get garbled circuit to send to Alice
    public GarbledGate[] getGarbledCircuit() {
        return garbledGates;
    }

    /**
     * Encode Bob's input by selecting the appropriate wire labels.
     * Bob knows his actual input values, so he selects the corresponding labels.
     *
     * @param bobInput Bob's 3-bit input [yA, yB, yR]
     * @return Wire labels corresponding to Bob's input values
     */
    public WireLabel[] encodeBobInput(int[] bobInput) {
        WireLabel[] encoded = new WireLabel[NUM_INPUT_BOB];
        for (int i = 0; i < NUM_INPUT_BOB; i++) {
            // Select label for value 0 or 1 based on Bob's actual input
            encoded[i] = wireLabels[3 + i][bobInput[i]].copy();
        }
        return encoded;
    }

    /**
     * Get both possible labels for Alice's input wires.
     * Alice will use Oblivious Transfer (OT) to get only the labels
     * corresponding to her actual input, without Bob learning which ones.
     *
     * @return Array of [wire][0/1 value] labels for Alice's 3 input wires
     */
    public WireLabel[][] getAliceInputLabels() {
        WireLabel[][] labels = new WireLabel[NUM_INPUT_ALICE][2];
        for (int i = 0; i < NUM_INPUT_ALICE; i++) {
            labels[i][0] = wireLabels[i][0].copy();
            labels[i][1] = wireLabels[i][1].copy();
        }
        return labels;
    }

    /**
     * Get decoding information for the output wire.
     * Alice uses this to translate her final wire label into the actual result.
     *
     * @return Array where [0] = label for false, [1] = label for true
     */
    public WireLabel[] getOutputDecoding() {
        return outputDecoding;
    }
}