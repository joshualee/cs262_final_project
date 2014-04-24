package edu.harvard.cs262.crypto;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Helpers {
	
	public static void doAsync(Runnable r) {
		ExecutorService pool = Executors.newFixedThreadPool(1);
		Future future = pool.submit(r);
	}

}
