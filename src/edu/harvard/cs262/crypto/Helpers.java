package edu.harvard.cs262.crypto;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;

/** Class to put all helper functions we needed.*/
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

}
