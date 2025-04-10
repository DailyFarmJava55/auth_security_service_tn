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
import telran.auth.dto.CustomerRegisterDto;
import telran.auth.service.CredentialService;

@RestController
@RequestMapping("/auth/customer")
@RequiredArgsConstructor
public class AuthCustomerController {
    private final CredentialService credentialService;

    @PostMapping("/register")
    public ResponseEntity<CredentialResponseDto> registerCustomer(@Valid @RequestBody CustomerRegisterDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(credentialService.registerCustomer(dto));
    }
}
