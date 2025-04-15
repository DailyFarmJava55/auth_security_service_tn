package telran.auth.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import telran.auth.dao.CredentialRepository;
import telran.auth.entity.Credential;
@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
	
	private final CredentialRepository credentialRepository;
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		Credential credential = credentialRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

		String role = credential.getUserIdsByRole().keySet().stream()
				.findFirst()
				.map(Enum::name)
				.orElseThrow(() -> new UsernameNotFoundException("No role found for user: " + email));

		return org.springframework.security.core.userdetails.User
				.withUsername(email)
				.password(credential.getHashedPassword())
				.authorities("ROLE_" + role)
				.build();
	}
}
