package edu.harvard.cs262.crypto;

public class ClientNotFound extends Exception {
   ClientNotFound(String s){
      System.out.println(s);
   }
}