package edu.harvard.cs262.crypto;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * VPrint class allows for printing data at varying levels of verbosity depending 
 * on the intended purpose. This class also serves as our logging mechanism 
 * and automatically writes all messages (regardless of verbosity) to the log
 * along with the time stamp.
 * 
 * @author Holly Anderson, Joshua Lee, and Tracy Lu
 */
public class VPrint {
	private final String logDirectory = "logs/";
	private final Path logPath;
	
	/**
	 * The verbosity hierarchy is cascading, so if you specify
	 * verbosity V, it will print all messages at level V and below.
	 * So a warn verbosity prints warning messages as well as normal messages.
	 */
	public static final int ALL = 8;
	public static final int DEBUG2 = 7;
	public static final int DEBUG = 6;
	public static final int WARN = 5;
	public static final int ERROR = 4;
	public static final int LOUD = 2;
	public static final int QUIET = 1;
	public static final int NONE = 0;
	public int verbosity;
	public BufferedWriter log;
	
	/** 
	 * Opens a log file
	 * @param logPath
	 * 		The path of the log file
	 * @return a BufferedWriter for writing to the log file
	 * Catches IOException if log file can't open
	 */
	private BufferedWriter openFile(Path logPath) {
		BufferedWriter bw;
		
		try {
			bw = Files.newBufferedWriter(logPath, 
				Charset.forName("UTF-8"), 
				new OpenOption[] {StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE}
			);
		} catch (IOException e) {
			System.out.println(String.format("[VPrint] Failed to open log file %s...", logPath));
			bw = null;
		}
		
		return bw;
	}
	
	/**
	 * Sets verbosity and opens log file
	 * @param verbosity
	 * 		Integer indicating verbosity level
	 * @param logFileName
	 * 		Name of log file to open
	 */
	public VPrint(int verbosity, String logFileName) {
		this.verbosity = verbosity;  
		logPath = Paths.get(logDirectory, logFileName);
		
		log = openFile(logPath);
	}
	
	private String getLevel(int v) {
		switch (v) {
		case NONE:
		case QUIET:
			return "";
		case LOUD:
			return "[LOUD] ";
		case ERROR:
			return "[ERROR] ";
		case WARN:
			return "[WARN] ";
		case DEBUG:
			return "[DEBUG] ";
		case DEBUG2:
			return "[DEBUG+] ";
		case ALL:
			return "[ALL] ";
		}
		return "";
	}
	
	/**
	 * Print the message as long as the printer is set to the
	 * appropriate verbosity.
	 * @param v
	 * 		Verbosity level
	 * @param format
	 * 		The desired print format
	 * @param args
	 * 		The stuff to format
	 */
	public void print(int v, String format, Object... args) {
		if (format == null || format.length() == 0) {
			return;
		}
		
		// log to file regardless of verbosity
		String s = String.format(format, args);
		s = String.format("%s%s", getLevel(v), s);
		
		try {
			if (log != null) {
				log.write(String.format("[%s] %s\n", Helpers.currentTime(), s));
				log.flush();
			}
		} catch(ClosedChannelException e) {
			log = openFile(logPath);
		} catch (IOException e) {
			System.out.println("[VPrint] Log write failed...");
		}
		
		if (v <= verbosity) {
			System.out.println(s);
		}
	}
}
