Distributed Cryptography
=============

Final project for CS262: Introduction to Distributed Systems (Harvard Spring 2014)

This project provides a framework that can be used to test the security of cryptographic protocols through simulations. The architecture consists of multiple clients that talk to each other through a server. Clients can speak to each other using plaintext or encrypted messages. Different key exchange and encryption protocols can easily be swapped in and out. Clients can also eavesdrop on other clients, simulating attackers trying to listen in on and break a secure session.

Ontop of this framework, we have built two simple applications:

#### Console Communicator

A console line application that provides a simple interface to send messages to other clients. Clients can also eavesdrop on other clients, simulating an attacker who is listening to the wire.

#### E-voting

Distributed electronic voting allows n parties to all vote on a ballot in such a manner that no party learns anything from seeing all the encrypted ballots, except the result of the vote (in particular each party cannot learn any other party’s vote). This property has obvious privacy advantages which can be especially important for sensitive votes.

Our application allows the server to start a vote by specifying a ballot. Clients are then able to vote for or against the ballot and the result is securely computed. Each client is also given each other client's public communication, giving other clients a chance to break the evoting protocol.

Authors
-------
* Holly Anderson (hollyanderson@fas.harvard.edu)
* Joshua Lee (joshualee@college.harvard.edu)
* Tracy Lu (tlu@college.harvard.edu)

CryptoClient
-------------

####Simple Client

Implements basic sending/receiving/eavesdropping of messages.

####DiffieHellman Client

Extends simple client but also has the ability to perform encrypted communcation. Designed to connect to `CentralServer`.

####EVote Client

Extends DiffieHellman Client but also has the ability to do evoting. Designed to connect to `EVoteServer`.

CryptoServer
-------------

####Central Server

Facilitates basic sending/receiving/eavesdropping of encrypted messages. Ensures connection to clients by using a "heartbeat" ping to the clients. Designed to accept connections from `DHCryptoClient`.

####EVote Server

Facilitates encrypted voting. Designed to accept connections from `EVoteClient`.

Compilation
-----------------
To compile all files run one of the following commands from the top level. If using Linux/Unix, run the first command; if using Windows, run the second. All class and stub files will be placed in the `bin/` directory. **Note that we require Java version 1.7.X **

	./compileNix.sh
	./compileWin.sh
	
Usage
-----------------
Run the following commands for the appropriate system from the top level, substituting the placeholders `$POLICY_FILE`, `$REGISTRY_PORT`, `$REGISTRY_IP`, and `$SERVER_NAME` with appropriate values. `$POLICY_FILE` can be replaced with one of two file names: `all.policy` or `general.policy`. The former is a blanket grant of permissions while the latter is more restricted (and recommended). `$REGISTRY_PORT` and `$REGISTRY_IP` correspond to the port and public IP address of the rmiregistry, respectively. Note that the IP of the rmiregistry will be the same as the IP of the machine on which the server is running. `$SERVER_NAME` is the name of the server.

####Encrypted Message System ("TestBed")

    java -Djava.security.policy=policies/$POLICY_FILE -cp bin edu.harvard.cs262.crypto.server.CentralServer $REGISTRY_PORT $SERVER_NAME

    java -Djava.security.policy=policies/$POLICY_FILE -cp bin edu.harvard.cs262.crypto.client.ClientConsole $REGISTRY_IP $REGISTRY_PORT $SERVER_NAME
   
####Electronic Voting System

    java -Djava.security.policy=policies/$POLICY_FILE -cp bin edu.harvard.cs262.crypto.server.EVoteServer $REGISTRY_PORT $SERVER_NAME

    java -Djava.security.policy=policies/$POLICY_FILE -cp bin edu.harvard.cs262.crypto.client.EVoteClient $REGISTRY_IP $REGISTRY_PORT $SERVER_NAME

Testing
--------------------
Run the one of the following commands from the top level to run all of our test files. If using Lunix/Unix, run the first command; if using Windows, run the second. Instructions on running one test at a time are found below.

	./testsNix.sh
	./testsWin.sh

#### Logs

Log files are written to the `log/` directory. Each log is titled by the name of the client or server who the log belongs to followed by the timestamp of which the log was created. Log entries are written by the VPrint (`VerbosePrint`) module. Using VPrint, application writers are able to specify the verbosity levels that are displayed to the user and printed to the log:

* **Quiet:** normal output
* **Loud:** verbose output
* **Error:** error messages
* **Warn:** warnings
* **Debug:** debugging information

#### JUnit Tests
To run any of these tests individually, execute one of the following commands from the top level, replacing $FILE_NAME with the appropriate file name.

Linux/Unix:

	java -cp "bin/:lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.$FILE_NAME
	
Windows:

	java -cp "bin/;lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.$FILE_NAME

* **ClientServerTests:** unit tests basic interaction between the client and server and among clients
* **CryptoCipherTests:** unit tests DiffieHellman key exchange and ElGamal cipher; also tests more complex client interaction (key exchange)
* **EVoteTests:** unit tests that evoting returns the expected result of the vote; also tests abort vote succeeds when a client fails to vote within a certain time window

#### Console Tests
To run this test individually, execute one of the following commands from the top level.

Linux/Unix:

	java -cp "bin/:lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.ConsoleTest
	
Windows:

	java -cp "bin/;lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.ConsoleTest
	
* **ConsoleTest:** tests the sending and receiving of encrypted and non encrypted messages among clients; also tests eavesdropping

#### Failure Tests

The most difficult aspect of the project was dealing with failure. We have a few automated tests that ensure our system continues to run despite failure (e.g. if a client takes too long to submit a vote during evoting). However the majority of this testing was done manually, due to technical limitations to automate the specific failure conditions (did not have time to set up a mock object testing framework such as Mockito or EasyMock). 

You can replicate our manual testing by starting up a server and multiple clients, running part of a task such as evoting or sending a message, and then shutting down one of the clients participating in the task. Our system should gracefully fail and notify the still-alive clients. Evote abortion and key exchange failure are good examples of this.
