package telran.auth.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import telran.auth.security.jwt.JwtAuthFilter;
import telran.auth.security.jwt.service.JwtService;
import telran.auth.security.jwt.service.RevokedTokenService;

@Configuration
public class FilterConfig {
	 @Bean
	    JwtAuthFilter jwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService,  RevokedTokenService revokedTokenService) {
	        return new JwtAuthFilter(jwtService,userDetailsService, revokedTokenService);
	    }
}
