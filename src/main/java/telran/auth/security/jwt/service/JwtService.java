package telran.auth.security.jwt.service;

import java.security.Key;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import telran.auth.entity.Role;

@Service
@Slf4j
public class JwtService {
	@Value("${jwt.accessExpirationSec:3600}") 
	private int accessExpirationSec;
	
	@Value("${jwt.refreshExpirationSec:604800}") // 7 days
	private int refreshExpirationSec;

	@Value("${jwt.secret}") // Secret key from application.properties
	private String secretKey;
	
	private Key getSigningKey() {
		log.debug("JwtService. Decoding secretKey for signing...");
		Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
		return key;
	}

	public String generateAccessToken(UUID userId, String email, Role role) {
	    String token = Jwts.builder()
	            .setSubject(email)
	            .claim("userId", userId.toString())
	            .claim("role", role.name()) 
	            .setIssuedAt(new Date(System.currentTimeMillis()))
	            .setExpiration(new Date(System.currentTimeMillis() + accessExpirationSec))
	            .signWith(getSigningKey())
	            .compact();

	    log.debug("Generated access token: {}", token);
	    return token;
	}

	public String generateRefreshToken(UUID userId, String email) {
		String token = Jwts.builder().setSubject(email).claim("userId", userId.toString())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + refreshExpirationSec * 1000))
				.signWith(getSigningKey()).compact();

		log.debug("JwtService. Generated refresh token: {}", token);
		return token;
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
			return true;
		} catch (JwtException e) {
			log.error("Invalid JWT token: {}", e.getMessage());
			return false;
		}
	}

	public UUID extractUserId(String token) {
		try {
			Claims claims = extractAllClaims(token);
			return UUID.fromString(claims.get("userId", String.class));
		} catch (JwtException e) {
			log.error("Failed to extract id from token: {}", e.getMessage());
			throw e;
		}
	}

	public String extractEmail(String token) {
		try {
			String subject = extractAllClaims(token).getSubject();
			return subject.toString();
		} catch (JwtException e) {
			log.error("Failed to extract email from token: {}", e.getMessage());
			throw e;
		}
	}
	
	public Role extractRole(String token) {
		try {
			String roleName = extractAllClaims(token).get("role", String.class);
			return Role.valueOf(roleName);
		} catch (Exception e) {
			log.error("Failed to extract role: {}", e.getMessage());
			throw new JwtException("Invalid role in token");
		}
	}
	
	

	public Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(getSigningKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}

	public Date getExpirationDate(String token) {
		return extractAllClaims(token).getExpiration();
	}

	public Date extractExpiration(String token) {
		log.debug("JwtService. Extracting expiration date from token...");
		return extractClaim(token, Claims::getExpiration);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		return claimsResolver.apply(extractAllClaims(token));
	}

	public boolean isTokenExpired(String token) {
		Date expiration = extractExpiration(token);
		boolean expired = expiration.before(new Date());

		return expired;
	}
}

