#!/bin/bash
(cd tests && javac -g -d ../bin -cp ../bin edu/harvard/cs262/tests/ConsoleTest.java)
(cd tests && javac -g -d ../bin -cp ../bin edu/harvard/cs262/tests/CryptoCommunicationTest.java)
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*.java)
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*/*.java)
(cd bin && rmic edu.harvard.cs262.crypto.server.CentralServer)