#!/bin/sh

variant=tl-pcsc
version=3.0.2-SNAPSHOT
mainclass=com.github.devnied.emvpcsccard.Main

mvn clean dependency:copy-dependencies package -rf :$variant
mvn_status=$?

if [ "$mvn_status" -eq "0 " ]
then
    java -cp $variant/target/$variant-$version.jar:$variant/target/dependency/*:$variant $mainclass
else
    echo mvn_status=$mvn_status
fi
