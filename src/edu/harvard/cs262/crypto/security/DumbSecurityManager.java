package edu.harvard.cs262.crypto.security;

import java.security.Permission;

public class DumbSecurityManager extends SecurityManager {
	  @Override
	  public void checkPermission(Permission perm) {
	    return;
	  }
}