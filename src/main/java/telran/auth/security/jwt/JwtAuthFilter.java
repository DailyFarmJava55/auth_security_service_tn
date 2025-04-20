package telran.auth.security.jwt;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import telran.auth.entity.Role;
import telran.auth.security.jwt.service.JwtService;
import telran.auth.security.jwt.service.RevokedTokenService;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter{
	
	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	private final RevokedTokenService revokedTokenService;
	
	private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/auth/customer/login",
            "/auth/farmer/login",
            "/auth/customer/register",
            "/auth/farmer/register",
            "/auth/customer/refresh",
            "/auth/farmer/refresh"
            
    );
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String uri = request.getRequestURI();
        log.debug("🔎 Checking URI: {}", uri);

        if (isPublicEndpoint(uri)) {
            log.debug("✅ Public endpoint. Skipping filter.");
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractToken(request);

        if (token == null || revokedTokenService.isRevorkedToken(token) || !jwtService.validateToken(token)) {
            log.warn("⚠️ Invalid or missing token");
            filterChain.doFilter(request, response);
            return;
        }

        String email = jwtService.extractEmail(token);
        Role role = jwtService.extractRole(token); // one role per token

        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            List.of(new SimpleGrantedAuthority("ROLE_" + role))
                    );

            SecurityContextHolder.getContext().setAuthentication(authToken);
            log.info("🔐 Authenticated user {} with role {}", email, role);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String uri) {
        return PUBLIC_ENDPOINTS.stream().anyMatch(uri::startsWith);
    }

    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}