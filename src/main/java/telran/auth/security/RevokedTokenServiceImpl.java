package telran.auth.security;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class RevokedTokenServiceImpl implements RevokedTokenService {
	private final Set<String> revokedTokens = ConcurrentHashMap.newKeySet();
	@Override
	public void revokeToken(String token) {
		 revokedTokens.add(token);
		
	}

	@Override
	public boolean isRevorkedToken(String token) {
		 return revokedTokens.contains(token);
	}
// TODO хранить отозванные токены в Redis или PostgreSQL
}
