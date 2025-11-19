#!/bin/bash

## Add folder
JAR_PATH="/home/user/Documents/AU/CryComp/Handins/AU2526F_Cryptographic-Computing/8/BF_IBE__BN-BLS__MPC-VSS/src/main/resources/jars/jpbc/"  

mvn install:install-file -Dfile="$JAR_PATH/jpbc-api-2.0.0.jar" -DgroupId=it.unisa.dia.gas -DartifactId=jpbc-api -Dversion=2.0.0 -Dpackaging=jar
mvn install:install-file -Dfile="$JAR_PATH/jpbc-crypto-2.0.0.jar" -DgroupId=it.unisa.dia.gas -DartifactId=jpbc-crypto -Dversion=2.0.0 -Dpackaging=jar
mvn install:install-file -Dfile="$JAR_PATH/jpbc-pbc-2.0.0.jar" -DgroupId=it.unisa.dia.gas -DartifactId=jpbc-pbc -Dversion=2.0.0 -Dpackaging=jar
mvn install:install-file -Dfile="$JAR_PATH/jpbc-benchmark-2.0.0.jar" -DgroupId=it.unisa.dia.gas -DartifactId=jpbc-benchmark -Dversion=2.0.0 -Dpackaging=jar
mvn install:install-file -Dfile="$JAR_PATH/jpbc-mm-2.0.0.jar" -DgroupId=it.unisa.dia.gas -DartifactId=jpbc-mm -Dversion=2.0.0 -Dpackaging=jar
mvn install:install-file -Dfile="$JAR_PATH/jpbc-plaf-2.0.0.jar" -DgroupId=it.unisa.dia.gas -DartifactId=jpbc-plaf -Dversion=2.0.0 -Dpackaging=jar

