package telran.auth.service;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.server.ResponseStatusException;

import feign.FeignException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import telran.auth.dao.CredentialRepository;
import telran.auth.dto.AuthRequestDto;
import telran.auth.dto.AuthResponseDto;
import telran.auth.dto.CredentialResponseDto;
import telran.auth.dto.CustomerCreatedResponseDto;
import telran.auth.dto.CustomerRegisterDto;
import telran.auth.dto.FarmerCreatedResponseDto;
import telran.auth.dto.FarmerRegisterDto;
import telran.auth.dto.TokenValidationResponseDto;
import telran.auth.entity.Credential;
import telran.auth.entity.Role;
import telran.auth.exception.UnauthorizedException;
import telran.auth.feign.CustomerClient;
import telran.auth.feign.FarmerClient;
import telran.auth.security.jwt.service.JwtService;
import telran.auth.security.jwt.service.RevokedTokenService;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialServiceImpl implements CredentialService {

	private final CustomerClient customerClient;
	private final FarmerClient farmerClient;
	private final CredentialRepository credentialRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final RevokedTokenService revokedTokenService;

	@Override
	@Transactional
	public CredentialResponseDto registerCustomer(CustomerRegisterDto dto) {
		log.info("Registering customer with email: {}", dto.getEmail());

		Credential credential = credentialRepository.findByEmail(dto.getEmail()).orElse(null);

		UUID userId = sendCustomerToService(dto);
		if (credential != null) {
			if (credential.getUserIdsByRole().containsKey(Role.CUSTOMER)) {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "Customer already registered with this email");
			}
			return addRoleToExistingCredential(credential, Role.CUSTOMER, userId);
		}

		Credential newCredential = createNewCredential(dto.getEmail(), dto.getPassword(), Role.CUSTOMER, userId);
		credentialRepository.save(newCredential);
		return buildResponseDto(newCredential);
	}

	@Override
	@Transactional
	public CredentialResponseDto registerFarmer(FarmerRegisterDto dto) {
		log.info("Registering farmer with email: {}", dto.getEmail());

		Credential credential = credentialRepository.findByEmail(dto.getEmail()).orElse(null);

		UUID userId = sendFarmerToService(dto);
		if (credential != null) {
			if (credential.getUserIdsByRole().containsKey(Role.FARMER)) {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "Farmer already registered with this email");
			}
			return addRoleToExistingCredential(credential, Role.FARMER, userId);
		}

		Credential newCredential = createNewCredential(dto.getEmail(), dto.getPassword(), Role.FARMER, userId);
		credentialRepository.save(newCredential);
		return buildResponseDto(newCredential);
	}

	private CredentialResponseDto addRoleToExistingCredential(Credential credential, Role role, UUID userId) {
		credential.getUserIdsByRole().put(role, userId);
		credentialRepository.save(credential);
		log.info("Added new role '{}' to existing credential with email {}", role, credential.getEmail());
		return buildResponseDto(credential);
	}

	private Credential createNewCredential(String email, String rawPassword, Role role, UUID userId) {
		Credential credential = Credential.builder().email(email).hashedPassword(passwordEncoder.encode(rawPassword))
				.build();
		credential.getUserIdsByRole().put(role, userId);
		return credential;
	}

	private CredentialResponseDto buildResponseDto(Credential credential) {
		return new CredentialResponseDto(credential.getId(), credential.getEmail(),
				credential.getUserIdsByRole().keySet(), credential.getUserIdsByRole());
	}

	private UUID sendCustomerToService(CustomerRegisterDto dto) {
		try {
			CustomerCreatedResponseDto response = customerClient.createCustomer(dto);
			return response.id();
		} catch (FeignException ex) {
			handleUserAlreadyExists(ex, "Customer", dto.getEmail());
			return null;
		}
	}

	private UUID sendFarmerToService(FarmerRegisterDto dto) {
		try {
			FarmerCreatedResponseDto response = farmerClient.createFarmer(dto);
			return response.id();
		} catch (FeignException ex) {
			handleUserAlreadyExists(ex, "Farmer", dto.getEmail());
			return null;
		}
	}

	private void handleUserAlreadyExists(FeignException ex, String userType, String email) {
		if (ex.status() == 403 || ex.status() == 409) {
			log.warn("{} already exists: {}", userType, email);
			throw new ResponseStatusException(HttpStatus.CONFLICT, userType + " already registered with this email");
		}
		log.error("Error calling {} service: {}", userType.toLowerCase(), ex.getMessage());
		throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, userType + " service error");
	}

	// ***********************************LOGIN********************************************

	@Override
	@Transactional
	public AuthResponseDto login(AuthRequestDto requestDto, Role expectedRole) {
		Credential credential = credentialRepository.findByEmail(requestDto.getEmail())
				.orElseThrow(() -> new UnauthorizedException("Invalid email or password"));

		if (!credential.getUserIdsByRole().containsKey(expectedRole)) {
			throw new UnauthorizedException("User does not have required role: " + expectedRole);
		}

		if (!passwordEncoder.matches(requestDto.getPassword(), credential.getHashedPassword())) {
			throw new UnauthorizedException("Invalid email or password");
		}

		UUID userId = credential.getUserIdsByRole().get(expectedRole);
		if (userId == null) {
			throw new UnauthorizedException("User doesn't have required role: " + expectedRole);
		}

		String accessToken = jwtService.generateAccessToken(userId, credential.getEmail(), expectedRole);

		String refreshToken = jwtService.generateRefreshToken(userId, credential.getEmail());
		credential.setRefreshToken(refreshToken);
		credential.setLastLogin(LocalDateTime.now());
		credentialRepository.save(credential);
		return new AuthResponseDto(accessToken, refreshToken, expectedRole);
	}
	// *******************************Logout+Refresh********************************************************

	@Override
	public String logout(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or invalid Authorization header");
		}

		String token = authHeader.substring(7);

		if (!jwtService.validateToken(token)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token");
		}

		revokedTokenService.revokeToken(token);
		return "Logged out successfully";
	}


	private void validateRefreshToken(String token) {
		if (!jwtService.validateToken(token)) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
		}
		if (revokedTokenService.isRevorkedToken(token)) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token has been revoked");
		}
	}

	@Override
	public AuthResponseDto refreshAccessTokenForCustomer(@RequestHeader("x-refresh-token") String refreshToken) {
		 validateRefreshToken(refreshToken);

		    String email = jwtService.extractEmail(refreshToken);
		    UUID userId = jwtService.extractUserId(refreshToken);

		    String newAccessToken = jwtService.generateAccessToken(userId, email, Role.CUSTOMER);
		    return new AuthResponseDto(newAccessToken, refreshToken, Role.CUSTOMER);
	}

	@Override
	public AuthResponseDto refreshAccessTokenForFarmer(@RequestHeader("x-refresh-token") String refreshToken) {
		  validateRefreshToken(refreshToken);

		    String email = jwtService.extractEmail(refreshToken);
		    UUID userId = jwtService.extractUserId(refreshToken);

		    String newAccessToken = jwtService.generateAccessToken(userId, email, Role.FARMER);
		    return new AuthResponseDto(newAccessToken, refreshToken, Role.FARMER);
	}

	@Override
	public TokenValidationResponseDto validateAccessToken(String token) {
	    if (!jwtService.validateToken(token)) {
	        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
	    }

	   // String email = jwtService.extractEmail(token);
	    UUID userId = jwtService.extractUserId(token);
	    Role role = jwtService.extractRole(token);

	    return new TokenValidationResponseDto(userId, role.name());
	}
}
