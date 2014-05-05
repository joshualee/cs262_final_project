package edu.harvard.cs262.crypto;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

/** Class to put all helper functions we needed
 *
 * @author Joshua Lee and Tracy Lu
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
