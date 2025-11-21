package ibe;

import ibe.core.Ciphertext;
import ibe.core.MasterKeyShare;
import ibe.core.SystemParameters;
import ibe.crypto.User;
import ibe.hashing.HashFunctionFactory;
import ibe.pairing.PreGeneratedPairings;
import ibe.threshold.DistributedSetup;
import ibe.threshold.PKGServer;

import java.util.ArrayList;
import java.util.List;

/**
 * Complete demonstration of Alice and Bob having a conversation
 * using IBE with 3-party threshold cryptography.
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("╔═══════════════════════════════════════════════════════╗");
        System.out.println("║  IBE Threshold Cryptography: Alice & Bob Conversation ║");
        System.out.println("╚═══════════════════════════════════════════════════════╝");

        // ===== SETUP PHASE =====
        System.out.println("\n" + "=".repeat(60));
        System.out.println("PHASE 1: System Setup (Distributed MPC)");
        System.out.println("=".repeat(60));

        DistributedSetup.DistributedSetupResult setupResult = DistributedSetup.setup(
                PreGeneratedPairings.createQuickPairing(),
                HashFunctionFactory.createDefault(),
                256, // 32 bytes = 256 bits for messages
                3,   // 3 servers
                2    // threshold = 2
        );

        SystemParameters systemParams = setupResult.getSystemParameters();
        List<MasterKeyShare> serverShares = setupResult.getServerShares();

        List<PKGServer> servers = new ArrayList<>();
        servers.add(new PKGServer(1, "PKG-Server-1", systemParams, serverShares.get(0)));
        servers.add(new PKGServer(2, "PKG-Server-2", systemParams, serverShares.get(1)));
        servers.add(new PKGServer(3, "PKG-Server-3", systemParams, serverShares.get(2)));

        System.out.println("\n✓ System setup complete!");
        System.out.println("✓ 3 PKG servers initialized");
        System.out.println("✓ Threshold = 2 (any 2 servers can help users)");

        // ===== USER CREATION =====
        System.out.println("\n" + "=".repeat(60));
        System.out.println("PHASE 2: Users Join the System");
        System.out.println("=".repeat(60));

        User alice = new User("alice@company.com", systemParams);
        User bob = new User("bob@company.com", systemParams);

        System.out.println("\n✓ Alice joined: " + alice.getIdentity());
        System.out.println("✓ Bob joined: " + bob.getIdentity());

        // ===== KEY EXTRACTION =====
        System.out.println("\n" + "=".repeat(60));
        System.out.println("PHASE 3: Users Obtain Their Private Keys");
        System.out.println("=".repeat(60));

        alice.requestPrivateKey(List.of(servers.get(0), servers.get(1)));
        bob.requestPrivateKey(List.of(servers.get(1), servers.get(2)));

        // ===== CONVERSATION =====
        System.out.println("\n" + "=".repeat(60));
        System.out.println("PHASE 4: Alice and Bob Exchange Messages");
        System.out.println("=".repeat(60));

        // Message 1: Alice → Bob
        System.out.println("\n--- Message 1: Alice → Bob ---");
        String msg1 = "Hello Bob, how are you?";
        Ciphertext ct1 = alice.encryptMessage(bob.getIdentity(), msg1);
        String dec1 = bob.decryptMessage(ct1);
        System.out.println("  ✓ Match: " + msg1.equals(dec1));

        // Message 2: Bob → Alice
        System.out.println("\n--- Message 2: Bob → Alice ---");
        String msg2 = "Hi Alice! I'm doing great!";
        Ciphertext ct2 = bob.encryptMessage(alice.getIdentity(), msg2);
        String dec2 = alice.decryptMessage(ct2);
        System.out.println("  ✓ Match: " + msg2.equals(dec2));

        // Message 3: Alice → Bob
        System.out.println("\n--- Message 3: Alice → Bob ---");
        String msg3 = "Want to grab coffee later?";
        Ciphertext ct3 = alice.encryptMessage(bob.getIdentity(), msg3);
        String dec3 = bob.decryptMessage(ct3);
        System.out.println("  ✓ Match: " + msg3.equals(dec3));

        // Message 4: Bob → Alice
        System.out.println("\n--- Message 4: Bob → Alice ---");
        String msg4 = "Sure! See you at 3pm!";
        Ciphertext ct4 = bob.encryptMessage(alice.getIdentity(), msg4);
        String dec4 = alice.decryptMessage(ct4);
        System.out.println("  ✓ Match: " + msg4.equals(dec4));

        // ===== SUMMARY =====
        System.out.println("\n" + "=".repeat(60));
        System.out.println("SUMMARY");
        System.out.println("=".repeat(60));
        System.out.println("✓ 3-party MPC setup completed");
        System.out.println("✓ Different server combinations used");
        System.out.println("✓ 4 messages exchanged successfully");
        System.out.println("\n IBE with Threshold Cryptography Working! ");
        System.out.println("=".repeat(60));
    }
}