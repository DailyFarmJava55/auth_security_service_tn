package telran.auth.dto;

import jakarta.persistence.Column;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class FarmerRegisterDto {
	@NotBlank
    String phone;

    @Email
    @NotBlank
    @Column(unique = true, nullable = false)
    String email;

    @NotBlank
    String password;

    @NotBlank(message = "FARM_NAME_IS_REQUIRED")
	String farmName;
	
	@Valid
	CoordinatesDto coordinates;
}
