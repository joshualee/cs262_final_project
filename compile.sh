#!/bin/bash
(cd tests && javac -g -d ../bin -cp ../bin edu/harvard/cs262/tests/*.java)
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*.java)
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*/*.java)
(cd bin && rmic edu.harvard.cs262.crypto.server.CentralServer)