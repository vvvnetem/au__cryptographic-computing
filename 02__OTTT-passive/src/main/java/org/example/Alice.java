package org.example;

public class Alice {
    private final static int n = 8;
    private int r;
    private int[][] Ma;
    private int bloodType;
    private int u;
    private int v;
    private int zb;

    public Alice() {
    }

    public void init(int bloodType, int r, int[][] Ma) {
        this.bloodType = bloodType;
        this.r = r;
        this.Ma = Ma;
    }

    public int send(){
        u = (bloodType + r) % n;
        return u;
    }

    public void receive(int[] message) {
        v = message[0];
        zb = message[1];
    }

    public int output(){
        return zb ^ Ma[u][v];
    }
}
