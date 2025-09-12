public class Bob {
    private final static int n = 8;
    private int s;
    private int[][] Mb;
    private int bloodType;
    private int u;
    private int v;

    public Bob() {
    }

    public void init(int bloodType, int s, int[][] Mb) {
        this.bloodType = bloodType;
        this.s = s;
        this.Mb = Mb;
    }

    public void receive(int u) {
        this.u = u;
    }

    public int[] send() {
        v = (bloodType + s) % n;
        int zb = Mb[u][v];

        return new int[]{v,zb};
    }


}
