import java.util.Random;

public class Main {
    public static void main(String[] args) {
        Random rand = new Random();
        int x = rand.nextInt(8);
        int y = rand.nextInt(8);

        Dealer dealer = new Dealer();
        Alice alice = new Alice();
        Bob bob = new Bob();

        dealer.Init();
        alice.init(x,dealer.giveR(), dealer.giveMa());
        bob.init(y, dealer.giveS(), dealer.giveMb());
        bob.receive(alice.send());
        alice.receive(bob.send());
        z = alice.output();

        System.out.println(z);
    }
}