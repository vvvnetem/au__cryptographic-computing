# Secure Two-Party Blood Type Compatibility (d-Homomorphic Encryption)

The project demonstrates a secure two-party computation (2PC) protocol for blood-type compatibility
using the Paillier cryptosystem with respect to additive homomorphism.

The computation allows Alice (the recipient) and Bob (the donor) to jointly compute blood-type
compatibility without revealing their private inputs.

Thus, the computation ensures that _Bob_ never learns the recipient’s blood type, while
_Alice_ only learns whether the blood donor is compatible or not (1 or 0).

The protocol flow can be viewed as follows:

```{java}
// Blood types (O−, O+, A−, A+, B−, B+, AB−, AB+) uses 3-bit encoding
// Junit is responsible for 8x8 exhaustive test   

m1 = Alice.Choose(x) // Alice encrypts recipient blood type bits and sends them to Bob
m2 = Bob.Transfer(y, m1) // Bob homomorphically evaluates compatibility and returns ciphertext
z = Alice.Retrieve(m2) // Alice decrypts and learns the compatibility result
```

## Running tests

The project can build and the tests can be run  after importing the project into `IntelliJ` IDE.

In case of manual compilation, `javac *.java` can be used to compile the java classes respectively.


