package edu.harvard.cs262.crypto;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Helpers {
	
	public static String currentTime() {
		Timestamp ts = new Timestamp((new Date()).getTime());
		return ts.toString();
	}
	
	public static String currentTimeForFile() {
		return new SimpleDateFormat("yyyy-MM-dd H-mm-ss").format(new Date());
	}

}
