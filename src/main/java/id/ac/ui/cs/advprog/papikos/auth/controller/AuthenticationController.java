package id.ac.ui.cs.advprog.papikos.auth.controller;

import id.ac.ui.cs.advprog.papikos.auth.dto.*;
import id.ac.ui.cs.advprog.papikos.auth.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register/tenant")
    public ResponseEntity<UserDto> registerTenant(@RequestBody RegisterUserRequest request) {
        // Add validation for request body (e.g., @Valid)
        UserDto userDto = authenticationService.registerTenant(request);
        return new ResponseEntity<>(userDto, HttpStatus.CREATED);
    }

    @PostMapping("/register/owner")
    public ResponseEntity<UserDto> registerOwner(@RequestBody RegisterUserRequest request) {
        UserDto userDto = authenticationService.registerOwner(request);
        return new ResponseEntity<>(userDto, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse loginResponse = authenticationService.login(request);
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> logout() {
        authenticationService.logout();
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/owners/{userId}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> approveOwner(@PathVariable Long userId) {
        UserDto updatedUser = authenticationService.approveOwner(userId);
        return ResponseEntity.ok(updatedUser);
    }

    @GetMapping("/users/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = authenticationService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/owners/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> getPendingOwners() {
        List<UserDto> pendingOwners = authenticationService.getPendingOwners();
        return ResponseEntity.ok(pendingOwners);
    }

    // Internal Endpoints
    @GetMapping("/users/{userId}/internal")
    // Consider adding security here, e.g., require a specific role or internal service token
    public ResponseEntity<UserDto> getInternalUserById(@PathVariable Long userId) {
        UserDto userDto = authenticationService.getInternalUserById(userId);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/users/internal")
    public ResponseEntity<List<UserDto>> getInternalUsersByIds(@RequestParam String ids) {
        List<UserDto> users = authenticationService.getInternalUsersByIds(ids);
        return ResponseEntity.ok(users);
    }
} 