package telran.auth.security.jwt.dao;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import telran.auth.security.jwt.entity.RevokedToken;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, UUID> {
	
	boolean existsByToken(String token);

}
