package telran.auth.security.jwt.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Entity
@Table(name = "token_blacklist")
@AllArgsConstructor
@Builder
public class RevokedToken {
	@UuidGenerator
	@Id
	private
	UUID id;
 @Column(nullable = false, unique = true)
  private String token;
 
 @Column(nullable = false)
    private LocalDateTime  expiresAt;

	public RevokedToken(String token, LocalDateTime  expirationTime) {
		this.token = token;
		this.expiresAt = expirationTime;
	}
}
