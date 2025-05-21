package id.ac.ui.cs.advprog.papikos.auth.exception;

import id.ac.ui.cs.advprog.papikos.auth.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.LinkedHashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Object>> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.NOT_FOUND, request, ex.getMessage());
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiResponse<Object>> handleConflictException(ConflictException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.CONFLICT, request, ex.getMessage());
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiResponse<Object>> handleBadRequestException(BadRequestException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.BAD_REQUEST, request, ex.getMessage());
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiResponse<Object>> handleUnauthorizedException(UnauthorizedException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.UNAUTHORIZED, request, ex.getMessage());
    }

    @ExceptionHandler(Exception.class) // Generic exception handler
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception ex, WebRequest request) {
        // Consider logging the exception here
        // logger.error("An unexpected error occurred: ", ex);
        return buildErrorResponse(ex, HttpStatus.INTERNAL_SERVER_ERROR, request, "An unexpected internal error occurred. Please contact support.");
    }

    private ResponseEntity<ApiResponse<Object>> buildErrorResponse(Exception ex, HttpStatus status, WebRequest request, String message) {
        // Optionally, create a more detailed error data object if needed
        Map<String, Object> errorDetails = new LinkedHashMap<>();
        errorDetails.put("path", request.getDescription(false).replace("uri=", ""));
        errorDetails.put("exceptionType", ex.getClass().getSimpleName());

        ApiResponse<Object> apiResponse = ApiResponse.<Object>builder()
                .status(status)
                .message(message)
                .data(errorDetails)
                .build();
        return new ResponseEntity<>(apiResponse, status);
    }
}