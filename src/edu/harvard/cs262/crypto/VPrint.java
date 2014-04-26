package edu.harvard.cs262.crypto;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class VPrint {
	private final String logDirectory = "logs/";
	
	/*
	 * The verbosity hierarchy is cascading, so if you specify
	 * verbosity V, it will print all messages at level V and below.
	 * So a warn verbosity prints warning messages as well as normal messages.
	 */
	public static final int ALL = 3;
	public static final int DEBUG = 2;
	public static final int WARN = 1;
	public static final int NORMAL = 0;
	public int verbosity;
	public BufferedWriter log;
	
	
	public VPrint(int verbosity, String logFileName) {
		this.verbosity = verbosity;
		
		Path writeFile = Paths.get(logDirectory, logFileName);
		try {
			log = Files.newBufferedWriter(writeFile, 
				Charset.forName("UTF-8"), 
				new OpenOption[] {StandardOpenOption.CREATE, StandardOpenOption.APPEND}
			);
		} catch (IOException e) {
			System.out.println("[VPrint] Failed to open log file...");
			log = null;
		}
	}
	
	private String getLevel(int v) {
		switch (v) {
		case NORMAL:
			return "";
		case WARN:
			return "[WARN] ";
		case DEBUG:
			return "[DEBUG] ";
		}
		return "";
	}
	
	/**
	 * Print the message as long as the printer is set to the
	 * appropriate verbosity.
	 * @param verbosity : the 
	 * @param format
	 * @param args
	 */
	public void print(int v, String format, Object... args) {
		// log to file regardless
		String s = String.format(format, args);
		s = String.format("%s%s", getLevel(v), s);
		
		try {
			if (log != null) {
				log.write(s + "\n");
				log.flush();
			}
		} catch (IOException e) {
			System.out.println("[VPrint] Log write failed...");
		}
		
		if (v <= verbosity) {
			System.out.println(s);
		}
	}
}
