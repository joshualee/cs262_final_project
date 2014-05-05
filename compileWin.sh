#!/bin/bash
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*.java)
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*/*.java)
(cd tests && javac -g -d ../bin -cp "../bin;../lib/junit.jar" edu/harvard/cs262/tests/*.java)
(cd bin && rmic edu.harvard.cs262.crypto.server.CentralServer)