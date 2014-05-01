Distributed Cryptography
=============

Project description goes here.

Completed as a final project for CS262: Introduction to Distributed Systems (Harvard Spring 2014).

Authors
-------
* Joshua Lee (joshualee@college.harvard.edu)
* Tracy Lu (tlu@college.harvard.edu)
* Holly Anderson (hollyanderson@fas.harvard.edu)

CryptoClient
-------------

####Simple Client

Implements basic sending/receiving/eavesdropping of messages.

####DiffieHellman Client

Extends simple client but also has the ability to perform encrypted communcation.

####EVote Client

Extends DiffieHellman Client but also has the ability to do evoting.

CryptoServer
-------------

####Central Server

Facilitates basic sending/receiving/eavesdropping of encrypted messages.

####EVote Server

Facilitates encrypted voting.

Compilation
-----------------
To compile all files run the following command from the top level. All class and stub files will be located in the bin directory.

	./compile.sh
	
Usage
-----------------
Run the following commands for the appropriate system from the top level, substituting the placeholders <REGISTRY_PORT>, <REGISTRY_IP>, and <SERVER_NAME> with appropriate values. The first two placeholders correspond to the port and public IP address of the rmiregistry, respectively. Note that the IP of the rmiregistry will be the same as the IP of the machine on which the server is running. The last placeholder is the name of the server.

(1) Encrypted Message System
    java -Djava.security.policy=policies/all.policy -classpath bin edu.harvard.cs262.crypto.server.CentralServer <REGISTRY_PORT> <SERVER_NAME>

    java -Djava.security.policy=policies/all.policy -classpath bin edu.harvard.cs262.crypto.server.ClientConsole <REGISTRY_IP> <REGISTRY_PORT> <SERVER_NAME> 
   
(2) Encrypted Voting System
    java -Djava.security.policy=policies/all.policy -classpath bin edu.harvard.cs262.crypto.server.EVoteServer <REGISTRY_PORT> <SERVER_NAME>

    java -Djava.security.policy=policies/all.policy -classpath bin edu.harvard.cs262.crypto.server.EVoteClient <REGISTRY_IP> <REGISTRY_PORT> <SERVER_NAME> 