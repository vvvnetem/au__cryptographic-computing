# Secure Two-Party Blood Type Compatibility (d-HE scheme)

The project demonstrates a secure two-party computation (2PC) protocol for blood-type compatibility
using d-HE scheme inspired by lecture notes and [vDGHV].

The computation allows Alice (the recipient) and Bob (the donor) to jointly compute blood-type
compatibility without revealing their private inputs.

Thus, the computation ensures that _Bob_ never learns the recipient’s blood type, while
_Alice_ only learns whether the blood donor is compatible or not (1 or 0).

The protocol flow can be viewed as follows:

```java
// Blood types (O−, O+, A−, A+, B−, B+, AB−, AB+) use 3-bit encoding
// JUnit performs exhaustive 8x8 tests   

m1 = Alice.Choose(x) // Alice encrypts recipient blood type bits and sends them to Bob
m2 = Bob.Transfer(y, m1) // Bob evaluates the function on Alice's ciphertext
z = Alice.Retrieve(m2) // Alice decrypts and learns the compatibility result
```

## Running tests

The project can build and the tests can be run  after importing the project into `IntelliJ` IDE.

In case of manual compilation, `javac *.java` can be used to compile the java classes respectively.

## Short reasoning and justification about paramtere choices

The handin instruction said we __do not have to choose parameters as large as the one mentioned in the example. however, you should choose parameters such that the scheme is “homomorphic enough” to evaluate the circuit__. 

During testing with initial parameters pBits=512, qBits=128, rBits=20, n=1024, and sSize≈64 some decryptions were incorrect when I runned HETest.java (e.g., A− → AB− returned 0 instead of 1). 
That happened because the homomorphic multiplications increased the internal noise beyond the safe threshold for correct decryption under the conservative noise
accounting used in the implementation. 
 
To fix this I increased pBits to 1024 (vastly larger modulus, more noise budget) and decreased rBits to 16 (smaller initial noise), keeping sSize=64. 

By switching to pBits=1024 the margin between 2*R_final and p was increased. 
So even if the noise bound estimate is still pessimistic, 
p is now so much larger that the check 2*R' < p holds and decryption succeeds.

So raising pBits to 1024 increases the allowed noise budget by 2^512 and 
therefore recovers correct decryption despite previously pessimistic noise growth.

With these choices the inequality 2·R_final < p holds comfortably for our depth-3 circuit, and all 8×8 compatibility tests passed. 
 
This parameter choice is intentionally for a demonstration implementation; 



Code snippet from `Alice.java`:

```{java}
  // Parameter choices (tuned for  demo):
        // At first I set the parameters based on [] to values: 
            // pBits ~ 512, 
            // qBits ~ 128, 
            // rBits ~ 20, 
            // n ~ 1024
            // 
            // With this defaul parameters the noise growth provided wrong result for decrpytion: I got 0 instead of 1 for compatibility A-, AB.


        int pBits = 1024; //I modifiedd the value for 1024 bit instead of 512 here, because the noise growth provided wrong result for decrpytion: I got 0 instead of 1 for compatibility A-, AB-. 
        int qBits = 128; // I kept value as it 
        int rBits = 16; // r_i \approx  2^20; to be between 16 and 32
        int numPublicElements = 1024;
        this.kp = DHE.keyGen(pBits, qBits, rBits, numPublicElements, rnd);

        // The subset size for encryption: small enough to keep noise small
        this.sSize = Math.max(8, numPublicElements / 16); // e.g., n/16 ~ 64
```

Code snippet from `DHE.java`:

```{java}
/**
 * Simple d-HE (lecture notes and vDGHV-inspired) implementation.
 *
 * Public key: y_i = p * q_i + 2 * r_i  (i = 1..n)
 * Secret key: p (odd)
 *
 * Encryption of bit m: choose subset S ⊆ {1..n}, compute
 *   c = m + sum_{i in S} y_i    (integer)
 *
 * Decryption: m = ((c mod p) mod 2)
 *
 * Ciphertext stores:
 *  - the integer c
 *  - an upper bound noiseBound on the "noise term" (≈ 2 * sum r_i and growth from multiplies)
 *  - the multiplicative level (depth)
 */

```


In the encryption step, each ciphertext is constructed as


$$c = m + \sum_{i \in S} y_i$$, where $S$ is a randomly chosen subset of the public key elements.

We select S by sampling a fixed number of indices uniformly at random (≈ n/16 elements).
This choice is a compromise between correctness and security:

### Correctness (noise control):

Each $y_i$ contains a small error term $2·r_i$.

If $S$ is very large, the sum of many $r_i$ increases the noise, and after several homomorphic operations the total noise may exceed $p$, breaking decryption. 

By using a moderate subset size (e.g., $|S| ≈ n/16$), the initial noise is small enough so that decryption still works after additions and a few multiplications.

### Security (hiding the plaintext):

If $S$ were extremely small or predictable, an attacker could approximate $c − m$ and learn which $y_i$ were included, leaking information about $r_i$.

Choosing $S$ randomly and large enough makes the ciphertext statistically look like a large, unpredictable sum of public values, hiding the bit $m$.

* large enough $|S|$ ciphertext statistically hides $m$
* small enough $|S|$ the noise stays below $p$, ensuring correct decryption

The fixed random subset size therefore gives a good balance between encryption security and correct decryption after homomorphic evaluation.

For real-world deployments I would select parameter selection from the literature or a standard library.


## Bibilography

```{biblatex}
@inproceedings{vDGHV2010,
  author    = {van Dijk, Marten and Gentry, Craig and Halevi, Shai and Vaikuntanathan, Vinod},
  title     = {Fully Homomorphic Encryption over the Integers},
  booktitle = {Advances in Cryptology -- EUROCRYPT 2010},
  series    = {Lecture Notes in Computer Science},
  volume    = {6110},
  year      = {2010},
  publisher = {Springer},
  pages     = {24--43},
  note      = {Extended version available as IACR ePrint 2009/616},
  url       = {https://eprint.iacr.org/2009/616}
}

@inproceedings{CLT13,
  author    = {Coron, Jean-S\'{e}bastien and Lepoint, Tancr\`{e}de and Tibouchi, Mehdi},
  title     = {Batch Fully Homomorphic Encryption over the Integers},
  booktitle = {Cryptographic Hardware and Embedded Systems -- CHES 2013},
  series    = {Lecture Notes in Computer Science},
  volume    = {8086},
  year      = {2013},
  publisher = {Springer},
  pages     = {315--335},
  note      = {Also available as IACR ePrint 2013/036},
  url       = {https://eprint.iacr.org/2013/036}
}

@misc{BonehLectures,
  author = {Boneh, Dan},
  title  = {Applied Cryptography (CS255) and Modern Cryptography (CS355) Lecture Notes},
  howpublished = {Stanford University},
  year = {2015},
  url  = {https://crypto.stanford.edu/~dabo/courses/}
}

@book{LindellKatz2014,
  author    = {Lindell, Yehuda and Katz, Jonathan},
  title     = {Introduction to Modern Cryptography},
  publisher = {Chapman and Hall / CRC},
  edition   = {2nd},
  year      = {2014},
  chapter   = {13},
  note      = {Section on homomorphic encryption},
  isbn      = {978-1466570269}
}
```
