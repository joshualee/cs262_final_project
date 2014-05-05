package edu.harvard.cs262.tests;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import edu.harvard.cs262.crypto.CryptoMessage;
import edu.harvard.cs262.crypto.cipher.*;
import edu.harvard.cs262.crypto.client.DHCryptoClient;
import edu.harvard.cs262.crypto.exception.ClientNotFound;
import edu.harvard.cs262.crypto.server.CentralServer;
import edu.harvard.cs262.crypto.server.CryptoServer;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * JUnit tests for the basic cryptography primitives used in our project.
 * Here we test:
 * (1) KeyExchange (DiffieHellman)
 * (2) Encryption/Decryption (ElGamal)
 * (3) Integration (proper client/server interaction)
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class CryptoCipherTests {
	
	static CryptoServer server;
	static DHCryptoClient c1, c2;
	
	@BeforeClass 
	public static void setup() {
		// dummy server
		server = new CentralServer("server"); 
		
		// dummy clients
		c1 = new DHCryptoClient("c1", server);
		c2 = new DHCryptoClient("c2", server);
		
		try {
			server.registerClient(c1);
			server.registerClient(c2);
		} catch (RemoteException e) {
			fail("client registration failed");
		}
	}
	
	@Test
	public void DiffieHellman() throws RemoteException, ClientNotFound, InterruptedException, ExecutionException {
		
		// need to different protocols to avoid race condition when generating random numbers
		final DiffieHellman dh = new DiffieHellman();
		final DiffieHellman dh2 = new DiffieHellman();
		dh.seed(262);
		dh2.seed(250);
		
		// use same protocol id so the two protocols can talk to each other
		dh2.setProtocolId(dh.getFullProtocolId());
		
		ExecutorService pool = Executors.newFixedThreadPool(1);
		
		Future<CryptoKey> k2Future = pool.submit(new Callable<CryptoKey>() {
			@Override
			public CryptoKey call() throws Exception {
				return dh2.reciprocate(c2, "c1");
			}
		});
		
		CryptoKey k1 = dh.initiate(c1, "c2");
		CryptoKey k2 = k2Future.get();
		
		BigInteger k1Priv = (BigInteger) k1.getPrivate();
		DHTuple k1DHT = (DHTuple) k1.getPublic();
		
		BigInteger k2Priv = (BigInteger) k2.getPrivate();
		DHTuple k2DHT = (DHTuple) k2.getPublic();
		
		assertEquals("1826878400", k1Priv.toString());
		assertEquals("2341", k1DHT.g.toString());
		assertEquals("31123", k1DHT.p.toString());
		assertEquals("28821", k1DHT.xhat.toString());
		
		assertEquals("1028069308", k2Priv.toString());
		assertEquals("2341", k2DHT.g.toString());
		assertEquals("31123", k2DHT.p.toString());
		assertEquals("19968", k2DHT.xhat.toString());
    }
	
	@Test
	public void ElGamal() {
		// set up valid key
		CryptoKey k = new CryptoKey();
		DHTuple dht = new DHTuple(BigInteger.valueOf(31123), BigInteger.valueOf(2341), BigInteger.valueOf(14013));
		k.setPublic(dht);
		k.setPrivate(new BigInteger("38292607"));
		
		// initialize cipher
		ElGamalCipher egc = new ElGamalCipher();
		egc.setKey(k);
		
		// test string functionality
		String testText = "this is a test";
		
		CryptoMessage cipherText = egc.encrypt(testText);
		String plainText = egc.decrypt(cipherText);
		assertEquals(testText, plainText);
		
		// test integer functionality
		BigInteger testInt = BigInteger.valueOf(30421);
		
		CryptoMessage cipherTextInt = egc.encryptInteger(testInt);
		String plainTextInt = egc.decryptInteger(cipherTextInt);
		assertEquals(testInt.toString(), plainTextInt);
	}
	
	@Test
	public void integration() throws RemoteException, ClientNotFound, InterruptedException {
		c1.dropKeys();
		c2.dropKeys();
		
		String testMessage = "hello c2"; 
		String testMessage2 = "whats up c1"; 
		
		String recvMessage = c1.sendEncryptedMessage("c2", testMessage, "");
		String recvMessage2 = c2.sendEncryptedMessage("c1", testMessage2, "");
		
		assertEquals(testMessage, recvMessage);
		assertEquals(testMessage2, recvMessage2);
		
		String testMessage3 = "another test message"; 
		String testMessage4 = "hello there"; 
		
		c1.dropKeys();
		c2.dropKeys();
		String recvMessage3 = c1.sendEncryptedMessage("c2", testMessage3, "");
		String recvMessage4 = c2.sendEncryptedMessage("c1", testMessage4, "");
		
		assertEquals(testMessage3, recvMessage3);
		assertEquals(testMessage4, recvMessage4);
	}
}
