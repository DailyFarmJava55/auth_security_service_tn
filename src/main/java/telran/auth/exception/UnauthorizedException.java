package telran.auth.exception;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorizedException extends RuntimeException {
    
	private static final long serialVersionUID = -4005428281257080965L;

	public UnauthorizedException(String message) {
        super(message);
    }
}
