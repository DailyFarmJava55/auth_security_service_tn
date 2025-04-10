package telran.auth.exception;

import java.time.LocalDateTime;

public record ErrorResponse(
		 LocalDateTime timestamp,
	        String errorCode,
	        String message
		) {

}
