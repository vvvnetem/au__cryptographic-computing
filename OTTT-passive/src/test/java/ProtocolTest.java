import org.example.Alice;
import org.example.Bob;
import org.example.Dealer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ProtocolTest {
    // same truth table as in Dealer
    private final static int[][] T = {
            {1,1,1,1,1,1,1,1},
            {1,0,1,0,1,0,1,0},
            {1,1,0,0,1,1,0,0},
            {1,0,0,0,1,0,0,0},
            {1,1,1,1,0,0,0,0},
            {1,0,1,0,0,0,0,0},
            {1,1,0,0,0,0,0,0},
            {1,0,0,0,0,0,0,0},
    };

    @Test
    public void testAllBloodTypeCombinations() {
        for (int aliceType = 0; aliceType < 8; aliceType++) {
            for (int bobType = 0; bobType < 8; bobType++) {
                System.out.printf("Testing Alice=%d, Bob=%d%n", aliceType, bobType);

                Dealer dealer = new Dealer();
                dealer.Init();

                Alice alice = new Alice();
                Bob bob = new Bob();

                alice.init(aliceType, dealer.giveR(), dealer.giveMa());
                bob.init(bobType, dealer.giveS(), dealer.giveMb());

                bob.receive(alice.send());
                alice.receive(bob.send());
                int z = alice.output();

                int expected = T[aliceType][bobType];
                assertEquals(expected, z,
                        String.format("Mismatch for Alice=%d, Bob=%d", aliceType, bobType));
            }
        }
        // all assertions passed
        System.out.println("All blood type combinations passed successfully!");
    }
}
