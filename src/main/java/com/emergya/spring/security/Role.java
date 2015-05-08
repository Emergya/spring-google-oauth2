package com.emergya.spring.security;

/**
 * Enum used to differ the user roles in the webapp
 * @author ogonzalez
 *
 */
public enum Role {
	//FIXME: Habrá que añadir los roles propios de la aplicación, por ejemplo: ADMIN, BASIC_USER, etc.
	ROLE_GOOGLE("ROLE_GOOGLE"), ROLE_ANONYMOUS("ROLE_ANONYMOUS"), ROLE_APP("ROLE_APP");
	
	String name;
	
	private Role(String role){
		this.name = role;
	}
	
	public String getName(){
		return name;
	}

}
