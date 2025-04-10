package telran.auth.service;

import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import telran.auth.dao.CredentialRepository;
import telran.auth.dto.*;
import telran.auth.entity.Credential;
import telran.auth.entity.Role;
import telran.auth.feign.CustomerClient;
import telran.auth.feign.FarmerClient;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialServiceImpl implements CredentialService {

    private final CustomerClient customerClient;
    private final FarmerClient farmerClient;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public CredentialResponseDto registerCustomer(CustomerRegisterDto dto) {
        log.info("Registering customer with email: {}", dto.getEmail());

        Credential credential = credentialRepository.findByEmail(dto.getEmail()).orElse(null);

        if (credential != null) {
            if (credential.getRole().contains(Role.CUSTOMER)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Customer already registered with this email");
            }
            UUID userId = sendCustomerToService(dto);
            return addRoleToExistingCredential(credential, Role.CUSTOMER, userId);
        }

        UUID userId = sendCustomerToService(dto);
        Credential newCredential = createNewCredential(dto.getEmail(), dto.getPassword(), Role.CUSTOMER, userId);
        credentialRepository.save(newCredential);

        return buildResponseDto(newCredential);
    }

    @Override
    @Transactional
    public CredentialResponseDto registerFarmer(FarmerRegisterDto dto) {
        log.info("Registering farmer with email: {}", dto.getEmail());

        Credential credential = credentialRepository.findByEmail(dto.getEmail()).orElse(null);

        if (credential != null) {
            if (credential.getRole().contains(Role.FARMER)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Farmer already registered with this email");
            }
            UUID userId = sendFarmerToService(dto);
            return addRoleToExistingCredential(credential, Role.FARMER, userId);
        }

        UUID userId = sendFarmerToService(dto);
        Credential newCredential = createNewCredential(dto.getEmail(), dto.getPassword(), Role.FARMER, userId);
        credentialRepository.save(newCredential);

        return buildResponseDto(newCredential);
    }

    private CredentialResponseDto addRoleToExistingCredential(Credential credential, Role role, UUID userId) {
        credential.getRole().add(role);
        credential.setUserId(userId);
        credentialRepository.save(credential);
        log.info("Updated existing credential with new role: {}", role);
        return buildResponseDto(credential);
    }

    private Credential createNewCredential(String email, String rawPassword, Role role, UUID userId) {
        return Credential.builder()
                .email(email)
                .hashedPassword(passwordEncoder.encode(rawPassword))
                .role(Set.of(role))
                .userId(userId)
                .build();
    }

    private CredentialResponseDto buildResponseDto(Credential credential) {
        return new CredentialResponseDto(
                credential.getId(),
                credential.getEmail(),
                credential.getRole(),
                credential.getUserId()
        );
    }

    private UUID sendCustomerToService(CustomerRegisterDto dto) {
        CustomerCreatedResponseDto response = customerClient.createCustomer(dto);
        return response.id();
    }

    private UUID sendFarmerToService(FarmerRegisterDto dto) {
        FarmerCreatedResponseDto response = farmerClient.createFarmer(dto);
        return response.id();
    }
}
