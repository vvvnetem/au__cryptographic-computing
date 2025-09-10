import java.util.Random;

public class Dealer {

    static int n = 8;
    static int[][] T = {
            {1,0,0,0,0,0,0,0},
            {1,1,0,0,0,0,0,0},
            {1,0,1,0,0,0,0,0},
            {1,1,1,1,0,0,0,0},
            {1,0,0,0,1,0,0,0},
            {1,1,0,0,1,1,0,0},
            {1,0,1,0,1,0,1,0},
            {1,1,1,1,1,1,1,1}
    };
    int[][] Ma;
    int[][] Mb;
    int r;
    int s;

    public void Init() {
        Random rand = new Random();

        r = rand.nextInt(8);
        s = rand.nextInt(8);

        // Mb = random
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                Mb[i][j] = rand.nextInt(2);
            }
        }

        //Ma = MB[i, j] ⊕ T[i − r mod n, j − s mod n]
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                Ma[i][j] = Mb[i][j] ^ T[(i - r) % n][(j - s) % n];
            }
        }


    }
    public int giveR() {
        return r;
    }

    public int[][] giveMa() {
        return Ma;
    }

    public int giveS() {
        return s;
    }

    public int[][] giveMb() {
        return Mb;
    }
}
