package telran.auth.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import telran.auth.security.JwtAuthFilter;
import telran.auth.security.JwtService;
import telran.auth.security.RevokedTokenService;

@Configuration
public class FilterConfig {
	 @Bean
	    JwtAuthFilter jwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService,  RevokedTokenService revokedTokenService) {
	        return new JwtAuthFilter(jwtService,userDetailsService, revokedTokenService);
	    }
}
