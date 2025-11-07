from random import randrange, shuffle
from hashlib import sha256

# R = Receiver (aka Alice)
# D = Donor (aka Bob)

#Encoding of the 3 bit input:
#1st bit = true if party X has A
#2nd bit = true if party X has B
#3rd bit = true if party X has +

lookup_table = [[1,0,0,0,0,0,0,0],
            [1,1,0,0,0,0,0,0],
            [1,0,1,0,0,0,0,0],
            [1,1,1,1,0,0,0,0],
            [1,0,0,0,1,0,0,0],
            [1,1,0,0,1,1,0,0],
            [1,0,1,0,1,0,1,0],
            [1,1,1,1,1,1,1,1]]

#Modular inversion algorithm 
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

#Precomputed from sage for efficiency
p = 1284752603447879431971065942738584007123
q = (p-1) // 2
k = 128 #Size of keys
g = (randrange(1,p)**2) % p


# Class representing the first party Alice
class Alice:

    def __init__(self, Xa, Xb, Xr) -> None:
        # store Alice's input b as an integer
        self.x = [Xa, Xb, Xr]
        # initialize sk and pk
        self.OTsk = 0
        # generate a group in Zp with prime order q and generator g 

    # =============== OT functionality ========================================

    #Generate the b'th pk with gen, the rest with ogen
    def OTchoose(self, b):
        pks = [0] * 2
        for i in range(2):
            # print(i)
            if i == b:
                self.OTsk = randrange(0,p)
                pks[i] = self.OTgen(self.OTsk)
            else:
                r = randrange(0,p)
                pks[i] = self.OTogen(r)
        return pks

    def OTretrieve(self, ciphers, b):
        return self.OTdec(self.OTsk, ciphers[b])

    def OTgen(self, sk):
        # print("sk", sk)
        pk = pow(g, sk, p)
        return (g, p, q, pk)

    #The input is a random integer r in [1, p-1]
    #Now we just square it to make sure it is in the subgroup.
    def OTogen(self, r):
        return (g, p, q, r**2 % p)

    #We first do the El Gamal decrypt, then decode using
    #method 3 from the appendix.
    def OTdec(self, sk, ciphertext):
        c1, c2 = ciphertext
        M = (c2 * modinv(pow(c1, sk, p), p)) % p
        if M <= q:
            return (M-1 + p )% p
        else:
            return (-M-1 +p) % p

    # ================ Garbled circuit part (NEW) ========================

    # Use OT three times
    # Return encoded input X
    def encode_gb(self, Bob):
        X = []
        for i in range(3):
            pks = self.OTchoose(self.x[i])
            # print("OTchoose")
            ciphertexts = Bob.OTtransfer(pks, i)
            # print("OTtransfer")
            X.append(self.OTretrieve(ciphertexts, self.x[i]))
            # print("output")
        return X 
    
    #Evaluates each gate in the circuit (XOR by 1 comes for free)
    def evaluate(self, F, X, Y):
        and1 = self.evaluate_and(X[0], Y[0], 1, F[0])
        and2 = self.evaluate_and(X[1], Y[1], 2, F[1])
        and3 = self.evaluate_and(X[2], Y[2], 3, F[2])
        and4 = self.evaluate_and(and1, and2, 4, F[3])
        Z = self.evaluate_and(and3, and4, 5, F[4])

        return Z

    #Submethod for evaluating an AND gate.
    #We do the naive approach with decrypting 4 ciphertexts and padding with 0s.
    def evaluate_and(self, K_l, K_r, gate_num, ciphertexts):
        K_output = None
        for i in range(4):
            success, output = decrypt(K_l, K_r, gate_num, ciphertexts[i])
            if success and K_output is not None:
                print("Abort, multiple valid decrypts")
                return None
            if success:
                K_output = output  
        return K_output

    #Decoding the output, using the decoding info d and the garbled output Z
    def decode_gb(self, d, Z):
        return 0 if Z == d[0] else (1 if Z == d[1] else None)


# Class representing the second party Bob
class Bob:

    #Bob generates a message with the result for his input
    #and any possible input from Alice, using the truth table
    def __init__(self, Ya, Yb, Yr) -> None:
        self.y = [Ya, Yb, Yr]
        self.e = []

    # ========= OT code =======================================================

    def OTtransfer(self, pks, index):
        ciphertexts = []
        for msg, pk in zip(self.e[index], pks):
            ciphertexts.append(self.OTenc(pk, msg))
        return ciphertexts
    
    #We first encode using method 3 from the appendix
    #then do El Gamal encryption
    def OTenc(self, pk, message):
        g,p,q,h = pk
        if pow((message+1),q,p) ==1:
            encoded = message+1 % p
        else:
            encoded = -(message+1)%p
        r = randrange(0,q)
        c1 = pow(g, r, p)
        c2 = (encoded*pow(h, r, p))%p
        return c1,c2


    # ========== Garbled circuit code (NEW) =====================================================

    def garble_and(self, K_l0, K_l1, K_r0, K_r1, gate_num, K_output0, K_output1):
        ciphertexts = []
        ciphertexts.append(encrypt(K_l0, K_r0, gate_num, K_output0))
        ciphertexts.append(encrypt(K_l0, K_r1, gate_num, K_output0))
        ciphertexts.append(encrypt(K_l1, K_r0, gate_num, K_output0))
        ciphertexts.append(encrypt(K_l1, K_r1, gate_num, K_output1))
        shuffle(ciphertexts)
        
        return ciphertexts

    # Return F,d and save e=(ex|ey) for later use
    def generate_gb(self):
        #Generate e (input keys)
        offset = randrange(0,2**k)
        for i in range(6):
            key1 = randrange(0,2**k)
            self.e.append([key1,key1^offset])
        
        #Generate intermediate keys 
        intermediate = []
        for i in range(4):
            key1 = randrange(0,2**k)
            intermediate.append([key1,key1^offset])

        #Generate d (output pair)
        key1 = randrange(0,2**k)
        d = [key1,key1^offset]
        
        #Generate F (That means picking an order for the gates)
        #We assume that we are only concerned with passive security,
        #so Alice and Bob have agreed where the XORs are.
        #The XORs by 1 correspond to swapping the two keys on the wire. 
        gate1 = self.garble_and(self.e[0][1],self.e[0][0],self.e[3][0],self.e[3][1], 1,intermediate[0][0],intermediate[0][1])
        gate2 = self.garble_and(self.e[1][1],self.e[1][0],self.e[4][0],self.e[4][1], 2,intermediate[1][0],intermediate[1][1])
        gate3 = self.garble_and(self.e[2][1],self.e[2][0],self.e[5][0],self.e[5][1], 3,intermediate[2][0],intermediate[2][1])
        gate4 = self.garble_and(intermediate[0][1],intermediate[0][0],intermediate[1][1],intermediate[1][0], 4,intermediate[3][0],intermediate[3][1])
        gate5 = self.garble_and(intermediate[2][1],intermediate[2][0],intermediate[3][0],intermediate[3][1], 5, d[0],d[1])
        F = [gate1,gate2,gate3,gate4,gate5]
        
        #Return F, d, keep e as private state
        return F, d

    # Return encoded input Y
    def encode_gb(self):
        return [k0 if yi == 0 else k1 for (k0,k1),yi in zip(self.e[3:],self.y)]
    
#Implementation of G(K_L, K_R, i) using sha256
def prf(K_l, K_r, gate_num):
    hash_a = sha256("".join([str(K_r), str(gate_num)]).encode('utf-8')).digest()
    hash_b = sha256("".join([str(K_l), str(gate_num)]).encode('utf-8')).digest()
    hash_output = bytes(a ^ b for a, b in zip(hash_a, hash_b)).hex()
    return [int(hash_output[0:32], 16), int(hash_output[32:64], 16)]

#Encryption of an output key in the garbling
def encrypt(K_l, K_r, gate_num, K_output):
    ciphertext = prf(K_l, K_r, gate_num)
    ciphertext[0] ^= K_output
    return ciphertext

#Decryption of an output key ciphertext in the evaluation
def decrypt(K_l, K_r, gate_num, ciphertext):
    prf_output = prf(K_l, K_r, gate_num)
    return ciphertext[1] == prf_output[1], ciphertext[0] ^ prf_output[0]

#Protocol call structure
def protocol_run(Xa, Xb, Xr, Ya, Yb, Yr):
    receiver = Alice(Xa, Xb, Xr)
    donor = Bob(Ya, Yb, Yr)
    
    #Bob does the initial processing
    F, d = donor.generate_gb()
    Y = donor.encode_gb()
    #Do the OTs for encoding Alice's input. In the last msg,
    #Bob will also send F,Y,d, modelled here as that Alice is given them as input.
    X = receiver.encode_gb(donor)

    print(F)
    print(d)
    print(Y)
    print(X)
    
    Z = receiver.evaluate(F, X, Y)
    res = receiver.decode_gb(d, Z)

    return res


if len(sys.argv) > 1:
    transcript = sys.argv[1]
else:
    print("No argument provided. Provide argument with .txt file of protocol transcript.")

with open(transcript, "r") as f:
    lines = f.readlines()

# Strip whitespace/newlines
lines = [line.strip() for line in lines]

# Parse each line into Python objects
F = ast.literal_eval(lines[0])
d = ast.literal_eval(lines[1])
Y = ast.literal_eval(lines[2])
X = ast.literal_eval(lines[3])
