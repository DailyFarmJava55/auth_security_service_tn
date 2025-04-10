package telran.auth.service;

import telran.auth.dto.CredentialResponseDto;
import telran.auth.dto.CustomerRegisterDto;
import telran.auth.dto.FarmerRegisterDto;

public interface CredentialService {
	CredentialResponseDto registerCustomer(CustomerRegisterDto dto);
	CredentialResponseDto registerFarmer(FarmerRegisterDto dto);

}
