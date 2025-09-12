import java.util.Random;

public class Main {
    public static void main(String[] args) {

        String[] bloodTypesAlice = {"AB+", "AB-", "A+", "A-", "B+", "B-", "O+", "O-"};
        String[] bloodTypesBob = {"O-", "O+", "B-", "B+", "A-", "A+", "AB-", "AB+"};

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
        int z = alice.output();

        System.out.println("Alice blood type: " + bloodTypesAlice[x]);
        System.out.println("Bob blood type: " + bloodTypesBob[y]);
        System.out.println(z == 0 ? "Bob cannot be a donor for Alice." : "Bob can donate blood to Alice.");
    }
}