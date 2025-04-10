package telran.auth.dao;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import telran.auth.entity.Credential;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {
	Optional<Credential> findByEmail(String email);
    boolean existsByEmail(String email);
}
