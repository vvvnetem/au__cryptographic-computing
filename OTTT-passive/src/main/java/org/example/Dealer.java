package org.example;

import java.util.Random;

public class Dealer {private final static int n = 8;
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

    private int[][] Ma = new int[n][n];
    private int[][] Mb = new int[n][n];
    private int r;
    private int s;

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
                int row = ((i - r) % n + n) % n; //to avoid negative indexes
                int col = ((j - s) % n + n) % n;
                Ma[i][j] = Mb[i][j] ^ T[row][col];
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
