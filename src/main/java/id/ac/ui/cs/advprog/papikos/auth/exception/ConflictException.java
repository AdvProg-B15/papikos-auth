package id.ac.ui.cs.advprog.papikos.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class ConflictException extends RuntimeException {
    public ConflictException(String message) {
        super(message);
    }
} 