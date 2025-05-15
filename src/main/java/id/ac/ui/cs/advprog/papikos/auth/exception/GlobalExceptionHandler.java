package id.ac.ui.cs.advprog.papikos.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Object> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.NOT_FOUND, request);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<Object> handleConflictException(ConflictException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.CONFLICT, request);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<Object> handleBadRequestException(BadRequestException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.BAD_REQUEST, request);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<Object> handleUnauthorizedException(UnauthorizedException ex, WebRequest request) {
        return buildErrorResponse(ex, HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(Exception.class) // Generic exception handler
    public ResponseEntity<Object> handleGenericException(Exception ex, WebRequest request) {
        // Log the exception for debugging
        // logger.error("An unexpected error occurred: ", ex);
        return buildErrorResponse(ex, HttpStatus.INTERNAL_SERVER_ERROR, request, "An unexpected error occurred");
    }

    private ResponseEntity<Object> buildErrorResponse(Exception ex, HttpStatus status, WebRequest request) {
        return buildErrorResponse(ex, status, request, ex.getMessage());
    }

    private ResponseEntity<Object> buildErrorResponse(Exception ex, HttpStatus status, WebRequest request, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", request.getDescription(false).replace("uri=", ""));
        // You can add more details to the error response if needed
        // body.put("trace", ex.getStackTrace()); // Be cautious with exposing stack traces

        return new ResponseEntity<>(body, status);
    }
} 