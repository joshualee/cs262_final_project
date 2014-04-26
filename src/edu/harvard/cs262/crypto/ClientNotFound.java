package edu.harvard.cs262.crypto;

public class ClientNotFound extends Exception {
	
	private String errorMessage = "";
	
   ClientNotFound(String s){
   		errorMessage = s;
      System.out.println(s);
   }

	public String getErrorMessage(){
		return errorMessage;
	}
}