package telran;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients(basePackages = "telran.auth.feign")
public class DailyFarmAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(DailyFarmAuthServiceApplication.class, args);
	}

}
