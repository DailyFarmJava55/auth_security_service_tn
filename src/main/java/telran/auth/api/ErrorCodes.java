package telran.auth.api;

public interface ErrorCodes {
	String BAD_REQUEST = "BAD_REQUEST";
    String NOT_FOUND = "NOT_FOUND"; 
    String CONFLICT = "CONFLICT";     
    String INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR";
    String UNAUTHORIZED = "Invalid email or password";
	
	
	String ORDER_NOT_FOUND = "error.order.not_found";
	String ORDER_ALREADY_CANCELLED = "error.order.already_cancelled";
	String SURPRISE_BAG_EMPTY = "error.surprise_bag.empty";
	String SURPRISE_BAG_NOT_AVAILABLE = "SurpriseBag is not available for order";
}
