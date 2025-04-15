package telran.auth.dto;

import static telran.auth.api.ValidationMessages.*;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthRequestDto {
	@NotBlank(message = EMAIL_IS_NOT_VALID)
	@Email(message = EMAIL_IS_NOT_VALID)
	private String email;
	
	@Size(min = 8, message = PASSWORD_IS_NOT_VALID)
	@NotBlank(message = PASSWORD_IS_REQUIRED)
    private String password;
}
