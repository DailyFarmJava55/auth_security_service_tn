package telran.auth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import telran.auth.dto.FarmerCreatedResponseDto;
import telran.auth.dto.FarmerRegisterDto;

@FeignClient(name = "farmer-service", url = "${farmer-service.url}")
public interface FarmerClient {
    @PostMapping("/internal/farmers")
    FarmerCreatedResponseDto createFarmer(@RequestBody FarmerRegisterDto dto);
}
