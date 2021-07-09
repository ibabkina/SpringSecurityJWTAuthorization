package org.merit.security.springsecurityjwt.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.merit.security.springsecurityjwt.services.MyUserDetailsService;
import org.merit.security.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component // Needs to be in Spring's radar in order to autowire this
public class JwtRequestFilter extends OncePerRequestFilter {
	
	@Autowired // so Spring gives access to them
	private MyUserDetailsService userDetailsService;
	
	@Autowired
	private JwtUtil jwtUtil;

	/*
	 * The filter examines the incoming requests for the JWT in the header. It looks
	 * at the right header to see if the JWT is valid.If it finds a valid JWT, it's gonna get
	 * the user details out of userDetailsService & save it in the security context. it needs 
	 * dependencies: userDetailesService to use userDetails, JwtUtil (if finds JWT) to verify
	 * if it's a valid JWT and to pull out userName from it.
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authorizationHeader = request.getHeader("Authorization");
		
		String username = null;
		String jwt = null;
		
		if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			jwt = authorizationHeader.substring(7); // gives a substring after "Bearer space"
			username = jwtUtil.extractUserName(jwt);
		}
		
		/*
		 * Once we have userDetails, we validate the token with the userDetails by using validateToken 
		 * method. we're checking if JWT is valid for the given user. Need to verify that if userName
		 * matches and JWT isn't expired.
		 */
		if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
			if(jwtUtil.validateToken(jwt, userDetails)) {
				
				/*
				 * If JWT isn't expired we create UsernamePasswordAuthenticationToken which is default token
				 * we've already seen: this is what spring security uses for managing authentication in the context 
				 * of userName & password. We create a new userName & password authentication token. We set the details
				 * which is basically what is in the request.
				 */
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				/*
				 * We set it into the context but only in the case of valid JWT. But we had to verify first that something 
				 * has not already gone into the security context (see the first if statement) means the securityContext
				 * doesn't already have an authenticated user.
				 */
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		
		}
		/*
		 * Now we need to continue the chain: pass the control to the next filter in the filter chain
		 * 
		 */
		filterChain.doFilter(request, response);	
		// after we put a filter => the last piece of the puzzle is to go to SecurityConfigurer and 
		// tell it to use that filter chain. We need to interject it into the filter chain: add sessionManagement.
	}

}
