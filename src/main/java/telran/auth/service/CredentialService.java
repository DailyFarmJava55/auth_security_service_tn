package telran.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import telran.auth.dto.AuthRequestDto;
import telran.auth.dto.AuthResponseDto;
import telran.auth.dto.CredentialResponseDto;
import telran.auth.dto.CustomerRegisterDto;
import telran.auth.dto.FarmerRegisterDto;
import telran.auth.dto.TokenValidationResponseDto;
import telran.auth.entity.Role;

public interface CredentialService {
	
	CredentialResponseDto registerCustomer(CustomerRegisterDto dto);
	
	CredentialResponseDto registerFarmer(FarmerRegisterDto dto);
	
	AuthResponseDto login(AuthRequestDto requestDto, Role expectedRole);
	
    String logout(HttpServletRequest request);
    
	AuthResponseDto refreshAccessTokenForFarmer( String refreshToken);

	AuthResponseDto refreshAccessTokenForCustomer( String refreshToken);

	TokenValidationResponseDto validateAccessToken(String token);

}
