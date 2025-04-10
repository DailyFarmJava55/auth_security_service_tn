package telran.auth.dto;

import java.util.Set;
import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import telran.auth.entity.Role;
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CredentialResponseDto {
    private UUID id;
    private String email;
    private Set<Role> role;
    private UUID userId;
}

