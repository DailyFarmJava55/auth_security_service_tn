package telran.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import telran.auth.dto.AuthRequestDto;
import telran.auth.dto.AuthResponseDto;
import telran.auth.dto.CredentialResponseDto;
import telran.auth.dto.CustomerRegisterDto;
import telran.auth.entity.Role;
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
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody AuthRequestDto requestDto) {
        AuthResponseDto response = credentialService.login(requestDto, Role.CUSTOMER);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        return ResponseEntity.ok(credentialService.logout(request));
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refreshToken(@RequestHeader("x-refresh-token") String refreshToken) {
        return ResponseEntity.ok(credentialService.refreshAccessTokenForCustomer(refreshToken));
    }
    
}
