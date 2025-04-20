package telran.auth.dto;

import java.util.UUID;

public record TokenValidationResponseDto(
        UUID userId,
        String role
) {}
