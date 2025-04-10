package telran.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import telran.auth.dto.CredentialResponseDto;
import telran.auth.dto.FarmerRegisterDto;
import telran.auth.service.CredentialService;

@RestController
@RequestMapping("/auth/farmer")
@RequiredArgsConstructor
public class AuthFarmerController {
    private final CredentialService credentialService;

    @PostMapping("/register")
    public ResponseEntity<CredentialResponseDto> registerFarmer(@Valid @RequestBody FarmerRegisterDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(credentialService.registerFarmer(dto));
    }
}
