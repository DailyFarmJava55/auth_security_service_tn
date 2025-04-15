package telran.auth.entity;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.MapKeyColumn;
import jakarta.persistence.MapKeyEnumerated;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "credentials")
@Getter@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Credential {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String hashedPassword;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_ids_by_role", joinColumns = @JoinColumn(name = "credential_id"))
    @MapKeyColumn(name = "role")
    @MapKeyEnumerated(EnumType.STRING)
    @Column(name = "user_id")
    @Builder.Default
    private Map<Role, UUID> userIdsByRole = new HashMap<>();

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    
}

