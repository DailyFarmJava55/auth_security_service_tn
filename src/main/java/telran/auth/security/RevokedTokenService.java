package telran.auth.security;

public interface RevokedTokenService {
	void revokeToken(String token);
    boolean isRevorkedToken(String token);
}
