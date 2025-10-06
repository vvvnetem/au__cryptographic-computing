package org.example;

import java.util.Arrays;

/**
 * WireLabel represents a cryptographic key used in garbled circuits.
 * Each wire in the circuit has two labels: one representing bit value 0, another for bit value 1.
 * These 128-bit random values serve as encryption/decryption keys for garbled gates.
 *
 * Security property: Wire labels look completely random and reveal nothing about
 * the actual bit value they represent (0 or 1).
 */
class WireLabel {
    int[] key; // 128 bits = 4 integers (32 bits each)

    /**
     * Create a new wire label with uninitialized key.
     * The key array will be filled with random values or copied from another label.
     */
    WireLabel() {
        key = new int[4];
    }

    /**
     * Create a new wire label by copying an existing key.
     *
     * @param key The 4-integer array representing a 128-bit key
     */
    WireLabel(int[] key) {
        this.key = Arrays.copyOf(key, 4);
    }

    /**
     * Create a deep copy of this wire label.
     * This ensures that modifying the copy doesn't affect the original.
     *
     * @return A new WireLabel with the same key values
     */
    WireLabel copy() {
        return new WireLabel(this.key);
    }

    /**
     * Check if two wire labels are equal by comparing their keys.
     * This is used to decode the output: Alice checks which output label she computed.
     *
     * @param obj The object to compare with
     * @return true if both wire labels have identical keys, false otherwise
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof WireLabel)) return false;
        return Arrays.equals(this.key, ((WireLabel) obj).key);
    }
}

/**
 * GarbledGate represents an encrypted truth table for a single gate.
 * Instead of a plaintext truth table, a garbled gate contains encrypted entries.
 *
 * Structure:
 * - Contains 4 ciphertext entries (even for unary gates like NOT)
 * - Each ciphertext is 8 integers: 4 for encrypted label + 4 for verification tag
 * - Entries are randomly shuffled so the evaluator can't determine which is which
 *
 * Evaluation:
 * - Alice tries to decrypt all 4 entries with her input wire labels
 * - Only one entry will decrypt successfully (verified by the tag)
 * - This reveals the output wire label without revealing intermediate values
 */
class GarbledGate {
    int[][] ciphertexts; // 4 ciphertexts, each is 8 integers (label + tag)

    /**
     * Create a new garbled gate with space for 4 encrypted entries.
     * Bob will fill these during the garbling process.
     */
    GarbledGate() {
        ciphertexts = new int[4][8]; // Changed from [4][4] to [4][8] to match implementation
    }
}

/**
 * SimulatedOT implements a simulated version of Oblivious Transfer (OT).
 *
 * Oblivious Transfer is a cryptographic protocol where:
 * - Bob (sender) has pairs of values: (label_0, label_1) for each input bit
 * - Alice (receiver) has a choice bit for each input
 * - Alice learns only the label corresponding to her choice
 * - Bob doesn't learn which label Alice chose
 *
 * In a real implementation, this would use cryptographic OT protocols like:
 * - RSA-based OT
 * - Diffie-Hellman based OT
 * - OT extensions for efficiency
 *
 * This simulation just directly gives Alice the labels she needs,
 * assuming both parties are honest (for demonstration purposes only).
 */
class SimulatedOT {
    /**
     * Simulate Oblivious Transfer: Alice receives only the wire labels
     * corresponding to her input bits.
     *
     * In a real secure implementation:
     * - Bob would not learn Alice's choice bits
     * - Alice would not learn the other labels
     * - This would use actual OT cryptographic protocols
     *
     * @param senderLabels Bob's pairs of labels: [wireIndex][0 or 1]
     * @param receiverChoices Alice's input bits: her actual values (0 or 1)
     * @return Array of wire labels corresponding to Alice's choices
     */
    public static WireLabel[] simulateOT(WireLabel[][] senderLabels, int[] receiverChoices) {
        WireLabel[] result = new WireLabel[receiverChoices.length];
        // For each input bit, select the label corresponding to Alice's value
        for (int i = 0; i < receiverChoices.length; i++) {
            result[i] = senderLabels[i][receiverChoices[i]].copy();
        }
        return result;
    }
}
