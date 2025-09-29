# Oblivious Transfer with El Gamal Encryption

This is a Java project built with Maven. It simulates a blood compatibility protocol between two parties, Alice and Bob.

## Description

When you run the program:

1. Random blood types are generated for **Alice** and **Bob**.
2. They run the protocol to determine blood compatibility.
3. At the end, the result is printed: whether **Bob can be a donor for Alice** or not.

Each time you run the `Main` class, **new random blood types** are generated.

To **test every scenario** systematically, the project includes the `OTTest` class.

- `testAllBloodTypePairings` – it tests all possible blood type combinations for Alice and Bob.
- `testAliceDecryptsWrongCiphertext` - tests that Alice cannot decrypt a ciphertext not intended for her.
- `testBobCannotDistinguishFakePublicKeys` - tests that Bob cannot distinguish between real and fake public keys.

---
## Prerequisites

- Java 24
- Maven 3.x

## Running Main

You can run the `Main` class in an IDE like IntelliJ or use Maven:

### Using Maven

1. Open a terminal in the project root directory.
2. Use Maven to compile and run the `Main` class:
```
$ mvn compile exec:java -Dexec.mainClass="org.example.Main"
```
Example output:
```
Alice's blood type: A-
Bob's blood type: AB+
Can Alice receive from Bob? No
```

## Running Tests
Again, you can use an IDE or Maven:
```
$ mvn test
```
This will run all the tests in `OTTest`.    
Example output:
```
Running OTTest
Testing all blood type pairings:
1. Passed: O- -> AB+ Expected: 1, Actual: 1
2. Passed: O+ -> AB+ Expected: 1, Actual: 1
3. Passed: B- -> AB+ Expected: 1, Actual: 1
...
63. Passed: AB- -> O- Expected: 0, Actual: 0
64. Passed: AB+ -> O- Expected: 0, Actual: 0
Testing Alice decrypting wrong ciphertext:
Honest Alice should get: 1
Corrupted Alice gets: 8460716201125983332137627198340657758961221210203267850620569021856628308787807236676340082577723560996408596359425720172622792609248791067262535041213174
Testing Bob cannot distinguish fake public keys:
Key 0 appears valid to Bob - can encrypt successfully
Key 1 appears valid to Bob - can encrypt successfully
Key 2 appears valid to Bob - can encrypt successfully
...
```
## Project Structure
```
BeDOZa-passive/
├─ src/
│  ├─ main/
│  │  └─ java/
│  │     └─ org/example/
           └─ Main.java
           └─ Alice.java
           └─ Bob.java
           └─ ELGamal.java
│  └─ test/
│     └─ java/
│        └─ org/example/OTTest.java
├─ pom.xml
└─ README.md 
```
