package org.merit.security.springsecurityjwt.models;

/*
 * This AuthenticationRequest is going to define the input argument
 * to my authenticate() method. This is what the user is gonna send 
 * in the PostRequest
 */
public class AuthenticationRequest {
	
	private String username;
	private String password;
	
	// Needed for serialization
	public AuthenticationRequest() {}
	
	public AuthenticationRequest(String username, String password) {
		this.username = username;
		this.password = password;
	}
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
	
}
