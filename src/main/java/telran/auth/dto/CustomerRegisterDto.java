package telran.auth.dto;


import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CustomerRegisterDto {
    @NotBlank
    String phone;

    @Email
    @NotBlank
    @Column(unique = true, nullable = false)
    String email;

    @NotBlank
    String password;

    String city;

    CoordinatesDto coordinates;

    @NotBlank
	@Pattern(regexp = "[A-Z][a-z]{1,20}([-\\s][A-Z][a-z]{1,20})*", message = "NAME_IS_NOT_VALID")
	String firstName;
	
	@NotBlank
	@Pattern(regexp = "[A-Z][a-z]{1,20}([-\\s][A-Z][a-z]{1,20})*", message = "LAST_NAME_IS_NOT_VALID")
	String lastName;
}

