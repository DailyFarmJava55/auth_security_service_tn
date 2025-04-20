package telran.auth.security.jwt.service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.auth.security.jwt.dao.RevokedTokenRepository;
import telran.auth.security.jwt.entity.RevokedToken;

@Service
@RequiredArgsConstructor
public class RevokedTokenServiceImpl implements RevokedTokenService {
	
	private final JwtService jwtService;
	private final RevokedTokenRepository revorkedTokenRepository;
	
	@Override
	public void revokeToken(String token) {
		if (!revorkedTokenRepository.existsByToken(token)) {
			LocalDateTime  expirationTime = Instant.ofEpochMilli(jwtService.extractExpiration(token).getTime())
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();
			revorkedTokenRepository.save(new RevokedToken(token, expirationTime));
		}
	}

	@Override
	public boolean isRevorkedToken(String token) {
		 return revorkedTokenRepository.existsByToken(token);
	}
// TODO хранить отозванные токены в Redis
}
