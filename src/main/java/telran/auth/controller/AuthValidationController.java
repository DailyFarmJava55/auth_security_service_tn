package telran.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import telran.auth.dto.TokenValidationResponseDto;
import telran.auth.service.CredentialService;

@RestController
@RequestMapping("/internal")
@RequiredArgsConstructor
public class AuthValidationController {
    private final CredentialService credentialService;
    
    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponseDto> validateToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }

        String token = authHeader.substring(7);
        return ResponseEntity.ok(credentialService.validateAccessToken(token));
    }
    

}
