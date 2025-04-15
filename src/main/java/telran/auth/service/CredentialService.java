package telran.auth.service;

import telran.auth.dto.AuthRequestDto;
import telran.auth.dto.AuthResponseDto;
import telran.auth.dto.CredentialResponseDto;
import telran.auth.dto.CustomerRegisterDto;
import telran.auth.dto.FarmerRegisterDto;
import telran.auth.entity.Role;

public interface CredentialService {
	CredentialResponseDto registerCustomer(CustomerRegisterDto dto);
	CredentialResponseDto registerFarmer(FarmerRegisterDto dto);
	AuthResponseDto login(AuthRequestDto requestDto, Role expectedRole);

}
