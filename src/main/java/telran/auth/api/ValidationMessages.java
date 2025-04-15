package telran.auth.api;

public interface ValidationMessages {
	String INVALID_QUANTITY = "Quantity must be greater than zero";
	String INVALID_CUSTOMER_ID = "Customer ID must not be null";
	String INVALID_SURPRISE_BAG_ID = "Surprise Bag ID must not be null";
	
	String EMAIL_IS_NOT_VALID = "Email is not valid";
	String NAME_IS_NOT_VALID = "Name is not valid";
	String LAST_NAME_IS_NOT_VALID = "Last name is not valid";
	String PHONE_NUMBER_IS_NOT_VALID = "Phone number is not valid";
	String PHONE_IS_REQUIRED = "Phone is required";
	
	String PASSWORD_IS_NOT_VALID = "Password must be at least 8 characters long";
	String PASSWORD_IS_REQUIRED = "Password is required";
	String OLD_NEW_PASSWORD_REQUARED = "Old password and new password - requared field";
	String OLD_PASSWORD_IS_NOT_CORECT= "Old password is not correct";
	
	String WRONG_USER_NAME_OR_PASSWORD = "Wrong user name or password";
	String USER_NOT_FOUND = "User is not found";
	String INVALID_TOKEN = "Invalid or expired JWT token";

}
