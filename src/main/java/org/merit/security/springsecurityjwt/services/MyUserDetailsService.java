package org.merit.security.springsecurityjwt.services;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
 // connect to an actual user repository to get userDetails for a given
 // userName
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// This method has to load your user from DB in real world app
		return new User("foo", "foo", new ArrayList<>()); //hardcoded here
	}

}
