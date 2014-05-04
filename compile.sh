#!/bin/bash
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*.java)
(cd src && javac -g -d ../bin edu/harvard/cs262/crypto/*/*.java)
(cd bin && rmic edu.harvard.cs262.crypto.server.CentralServer)