package id.ac.ui.cs.advprog.papikos.auth.controller;

import id.ac.ui.cs.advprog.papikos.auth.dto.*;
import id.ac.ui.cs.advprog.papikos.auth.service.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID; // Import UUID

@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Healthcheck endpoint.
     *
     * @return ResponseEntity with "OK" status.
     */
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("OK");
    }

    /**
     * Registers a new tenant.
     *
     * @param request The registration request.
     * @return ResponseEntity with the created UserDto.
     */
    @PostMapping("/tenant/new")
    public ResponseEntity<UserDto> registerTenant(@RequestBody RegisterUserRequest request) {
        UserDto userDto = authenticationService.registerTenant(request);
        return new ResponseEntity<>(userDto, HttpStatus.CREATED);
    }

    /**
     * Registers a new owner.
     *
     * @param request The registration request.
     * @return ResponseEntity with the created UserDto.
     */
    @PostMapping("/owner/new")
    public ResponseEntity<UserDto> registerOwner(@RequestBody RegisterUserRequest request) {
        UserDto userDto = authenticationService.registerOwner(request);
        return new ResponseEntity<>(userDto, HttpStatus.CREATED);
    }

    /**
     * Logs in a user or admin.
     *
     * @param request The login request.
     * @return ResponseEntity with the LoginResponse containing token and user details.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse loginResponse = authenticationService.login(request);
        return ResponseEntity.ok(loginResponse);
    }

    /**
     * Logs out the currently authenticated user.
     *
     * @return ResponseEntity with no content.
     */
    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> logout() {
        authenticationService.logout();
        return ResponseEntity.noContent().build();
    }

    /**
     * Approves an owner registration. Requires ADMIN role.
     *
     * @param userId The UUID of the owner to approve.
     * @return ResponseEntity with the updated UserDto.
     */
    @PatchMapping("/owner/{userId}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> approveOwner(@PathVariable UUID userId) { // Changed to UUID
        UserDto updatedUser = authenticationService.approveOwner(userId);
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Gets the details of the currently authenticated user.
     *
     * @return ResponseEntity with the UserDto.
     */
    @GetMapping("/user/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserDto> getCurrentUser() {
        UserDto userDto = authenticationService.getCurrentUser();
        return ResponseEntity.ok(userDto);
    }

    /**
     * Gets a list of owners pending approval. Requires ADMIN role.
     *
     * @return ResponseEntity with a list of UserDto.
     */
    @GetMapping("/owner/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> getPendingOwners() {
        List<UserDto> pendingOwners = authenticationService.getPendingOwners();
        return ResponseEntity.ok(pendingOwners);
    }

    /**
     * Verifies an authentication token provided in a custom header.
     * This endpoint is intended for internal service-to-service communication.
     *
     * @param token The authentication token from the 'X-Internal-Auth-Token' header.
     * @return ResponseEntity indicating token validity (200 OK if valid, 401 Unauthorized if invalid).
     */
    @PostMapping("/auth/verify-internal")
    public ResponseEntity<Void> verifyInternalToken(@RequestHeader("X-Internal-Auth-Token") String token) {
        boolean isValid = authenticationService.verifyToken(token);
        if (isValid) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    // Internal Endpoints

    /**
     * Retrieves a user by ID for internal services.
     *
     * @param userId The UUID of the user.
     * @return ResponseEntity with the UserDto.
     */
    @GetMapping("/user/{userId}/internal")
    // Consider adding security here, e.g., require a specific role or internal service token
    public ResponseEntity<UserDto> getInternalUserById(@PathVariable UUID userId) { // Changed to UUID
        UserDto userDto = authenticationService.getInternalUserById(userId);
        return ResponseEntity.ok(userDto);
    }

    /**
     * Retrieves multiple users by a comma-separated list of IDs for internal services.
     *
     * @param ids A comma-separated string of user UUIDs.
     * @return ResponseEntity with a list of UserDto.
     */
    @GetMapping("/user/internal")
    public ResponseEntity<List<UserDto>> getInternalUsersByIds(@RequestParam String ids) {
        List<UserDto> users = authenticationService.getInternalUsersByIds(ids);
        return ResponseEntity.ok(users);
    }
}