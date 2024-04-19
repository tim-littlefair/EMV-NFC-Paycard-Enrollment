#!/bin/sh

variant=tl-pcsc
version=3.0.2-SNAPSHOT
mainclass=com.github.devnied.emvpcsccard.Main

java -cp $variant/target/$variant-$version.jar:$variant/target/dependency/*:$variant $mainclass
