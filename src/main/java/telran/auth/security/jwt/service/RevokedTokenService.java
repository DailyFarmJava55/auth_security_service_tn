package telran.auth.security.jwt.service;

public interface RevokedTokenService {
	void revokeToken(String token);
    boolean isRevorkedToken(String token);
}
