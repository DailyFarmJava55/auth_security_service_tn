package telran.auth.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import telran.auth.dto.CustomerCreatedResponseDto;
import telran.auth.dto.CustomerRegisterDto;

@FeignClient(name = "customer-service", url = "${customer-service.url}")
public interface CustomerClient {
    @PostMapping("/internal/customers")
    CustomerCreatedResponseDto createCustomer(@RequestBody CustomerRegisterDto dto);
}
