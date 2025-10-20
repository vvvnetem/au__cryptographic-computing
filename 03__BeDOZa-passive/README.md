# BeDOZa-passive

This is a Java project built with Maven. It simulates a blood compatibility protocol between two parties, Alice and Bob.

## Description

When you run the program:

1. Random blood types are generated for **Alice** and **Bob**.
2. They run the protocol to determine blood compatibility.
3. At the end, the result is printed: whether **Bob can be a donor for Alice** or not.

Each time you run the `Main` class, **new random blood types** are generated.

To **test every scenario** systematically, the project includes the `TestBeDOZa` class. The main test is:

- `testAllBloodTypeCompatibilities` – it tests all possible blood type combinations for Alice and Bob.

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
Alice blood type: A-
Bob blood type: A+
Alice learns the result: Bob cannot be a donor for Alice. 
```

## Running Tests
Again, you can use an IDE or Maven:
```
$ mvn test
```
This will run testAllBloodTypeCombinations in ProtocolTest.
Example output:
```
Running TestBeDOZa
1. Passed: O- -> O- Expected: 1, Actual: 1
2. Passed: O- -> O+ Expected: 1, Actual: 1
3. Passed: O- -> B- Expected: 1, Actual: 1
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
           └─ Delaer.java
│  └─ test/
│     └─ java/
│        └─ org/example/TestBeDOZa.java
├─ pom.xml
└─ README.md 
```
