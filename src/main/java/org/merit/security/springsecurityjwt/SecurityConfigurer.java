package org.merit.security.springsecurityjwt;

import org.merit.security.springsecurityjwt.filters.JwtRequestFilter;
import org.merit.security.springsecurityjwt.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	
	@Autowired
	private JwtRequestFilter jwtRequestFilter;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(myUserDetailsService);
	}
	
	/*
	 * It's disables cross-site request forgery and then it authorizes requests 
	 * for a "/authenticate" to everybody, and then any other request needs to be authenticated.
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
			.authorizeRequests().antMatchers("/authenticate").permitAll()
			.anyRequest().authenticated()
			.and().sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			/* Add sessionManagement to be stateless, tell Spring Security not to bother
			 * creating a session because the whole reason we're doing JWT is to make it stateless. 
			 */
	
	   /* If Spring Security is not creating a session then it needs to be something that works 
		* for each request and sets up the security context each time. That's why we need to add
		* the filter we created, jwtRequestFilter, before the UsernamePasswordAuthenticationFilter.
		* And we need to @Autowire it in this class. Spring security will call it first.
		*/
		http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	}

	
	/*
	 * Needs to be created to pass the Spring Security error "Consider defining a bean of 
	 * type 'org.springframework.security.authentication.AuthenticationManager' in your 
	 * configuration.
	 */
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
}
