package edu.harvard.cs262.crypto;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

/** Class to put all global helper functions we need.
 *
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class Helpers {
	
	/** Gives the current time in string format */
	public static String currentTime() {
		Timestamp ts = new Timestamp((new Date()).getTime());
		return ts.toString();
	}
	
	/** Gives the current date/time in specified format */
	public static String currentTimeForFile() {
		return new SimpleDateFormat("yyyy-MM-dd H-mm-ss").format(new Date());
	}
	
	/**
	 * A scanner that does not automatically close. This is necessary because when a thread
	 * that uses a scanner is interrupted, the thread will automatically close the underlying
	 * file stream. This is a problem when the file stream because cloesd is System.in, which
	 * we need to accept user input
	 * @param s
	 * 		the desired input stream
	 * @return
	 * 		the non closable scanner
	 */
	public static Scanner nonClosingScanner(InputStream s) {
		InputStream inStream = new FilterInputStream(System.in) {
		    @Override
		    public void close() throws IOException {
		    	System.out.println("[Helpers] Attemping to close stream...");
		        //don't close! 
		    }
		};
		
		Scanner scan = new Scanner(inStream);
		return scan;
	}
	
	/**
	 * When the scanner is interrupted during user input, it can be placed it a bad state where
	 * it believes its scanner buffer is empty, causing nasty exceptions. This is fixed by
	 * having the user hit enter, which resets the buffer properly.
	 * @param s the scanner
	 * @return
	 * 	the same as s.hasNextLine(), but handles exceptions
	 */
	public static boolean concurrentHasNextLine(Scanner s) {
		boolean res = false;
		
		try {
			res = s.hasNextLine();	
		} catch (Exception e) {
			System.out.println("Please hit enter to enable voting.");
		}
		
		return res;
	}
}
