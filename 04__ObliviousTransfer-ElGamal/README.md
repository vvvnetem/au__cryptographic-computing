# Oblivious Transfer for Blood Type Compatibility

Our implementation includes the following classes: 

* `Alice`: The class represents the receiver in an Oblivious Transfer protocol using ElGamal encryption.
* `Bob`: The class acts as the sender in an Oblivious Transfer protocol using ElGamal encryption.
* `ElGamal`: Implementation of the ElGamal public-key encryption scheme over a safe prime group with implementation of key pair generation, encryption, and decryption.
* `Main`: The class used as a demonstration for Blood Type Compatibility using Secure ElGamal Encryption
* `OTTest`: The class verifies the privacy-preserving blood type compatibility protocol implemented with ElGamal encryption and validates that the encrypted protocol result matches the expected compatibility for all 64 combinations. 


## Automated Testing

Our project uses:

* java-25-openjdk
* Apache Maven, maven-surefire-plugin 3.1.2
* JUnit 5 (junit-jupiter 5.10.0)

The easiest way is to test our implementation is to import our project into IntelliJ IDE
then run build and run `test/java/OTTest`. 

### IntelliJ Project Structure

```
├── pom.xml
├── src
│   ├── main
│   │   └── java
│   │       └── org
│   │           └── example
│   │               ├── Alice.java
│   │               ├── Bob.java
│   │               ├── ElGamal.java
│   │               └── Main.java
│   └── test
│       └── java
│           └── OTTest.java
└── target
    ├── classes
    │   └── org
    │       └── example
    │           ├── Alice.class
    │           ├── Bob.class
    │           ├── ElGamal$Ciphertext.class
    │           ├── ElGamal$KeyPair.class
    │           ├── ElGamal$PublicKey.class
    │           ├── ElGamal$SecretKey.class
    │           ├── ElGamal.class
    │           └── Main.class
    ├── generated-sources
    │   └── annotations
    ├── generated-test-sources
    │   └── test-annotations
    └── test-classes
        └── OTTest.class
```

## Manual Setup (Fresh Install, manual compilation)

In case we have a newly installed Operating System we need to
have the specific packages installed.

For testing purpose Fedora 42 was used (https://docs.fedoraproject.org/en-US/fedora/f42/).

The necessary packages can be installed with `dnf` package manager: 

`sudo dnf install -y java-25-openjdk java-25-openjdk-devel maven`

### Select the proper Java 25 binaries

To make sure maven will use the correct sdk we have to select the correct java binary. 

To do so we can use `sudo update-alternatives --config java`

```{bash}
There are 3 programs which provide 'java'.

  Selection    Command
-----------------------------------------------
*  1           /usr/lib/jvm/java-21-openjdk/bin/java
   2           /usr/lib/jvm/java-24-openjdk/bin/java
 + 3           /usr/lib/jvm/java-25-openjdk/bin/java

Enter to keep the current selection[+], or type selection number: 3
```


Similalry we have to select `javac` binary: 

sudo update-alternatives --config javac

```{bash}
There are 3 programs which provide 'javac'.

  Selection    Command
-----------------------------------------------
   1           /usr/lib/jvm/java-24-openjdk/bin/javac
*  2           /usr/lib/jvm/java-21-openjdk/bin/javac
 + 3           /usr/lib/jvm/java-25-openjdk/bin/javac

Enter to keep the current selection[+], or type selection number: 
```

###  Runnig `mvn` test

After succesfull installation of the packages Maven test can be run from the project's root directory with `mvn test -e`.

```{bash}
# Snippet after succesfull build/testing
[INFO] Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 65.17 s -- in OTTest
[INFO] 
[INFO] Results:
[INFO] 
[INFO] Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  01:06 min
[INFO] Finished at: 2025-09-29T12:02:26+02:00
[INFO] ------------------------------------------------------------------------

```




