package org.merit.security.springsecurityjwt.util;

/*
 * To abstract out all the JWT related stuff
 * Allow to create new JWTs given userDetails object 
 * and pull out information from an existing JWT (lookup userName from JWT,
 * expiration date, etc.)
 */

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {
	
	private String SECRET_KEY = "secret";
	
	/*
	 * Pulls info from an existing token.
	 */
	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	/*
	 * Pulls info from an existing token.
	 */
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	
	/* Pulls info from an existing token.
	 * Takes in a token and then uses a claimsResolver to figure out what the claims are.
	 * This is a way to get the data out
	 */
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	public Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
	}
	 private Boolean isTokenExpired(String token) {
		 return extractExpiration(token).before(new Date()); 
	 }
	 
	 /*
	  * UserDetailsService gives userDetails. This method creates a JWT for the userName based off
	  * on these userDetails, takes userName from userDetails and makes it into the JWT.
	  */
	 public String generateToken(UserDetails userDetails) {
		 
		 // You can create specific claims that you want to include in JWT - anything 
		 // that you want to include in the payload.
		 Map<String, Object> claims = new HashMap<>();
		 return createToken(claims, userDetails.getUsername());	 
	 }
	 
	 /*
	  * You can pass specific claims that you want to include in JWT - anything 
	  * that you want to include in the payload.
	  * 
	  * Calls JWT API that we included in the pom.XML. It uses the builder pattern 
	  * and it's setting the claims that we passed in. It sets a subject. 
	  * The subject is a person who is being authenticated who has successfully 
	  * authenticated.
	  * IssuedAt Date is the current date. Expiration Date (10 hours from now in this case) -
	  * can be anything depending on implementation. 
	  * It uses .signWith() method to sign the token.
	  * Secret key you passed in must be something more complicated.
	  * .compact() builds a pattern here.
	  * This is a builder pattern used by the JWT API that we've chosen for this project.
	  * There is a bunch more API's and JWT dependencies that you can use.
	  */
	 public String createToken(Map<String, Object> claims, String subject) {
		 return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				 .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 10))
				 .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	 }
	 
	 /*
	  * Takes in a token, extracts userName and then checks if that userName is same as
	  * the userName in the userDetails thats passed in. Also checkes if the token 
	  * isn't expired.
	  */
	 public Boolean validateToken(String token, UserDetails userDetails) {
		 final String username = extractUserName(token);
		 return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	 }
	 
}
