package id.ac.ui.cs.advprog.papikos.auth.controller;

import id.ac.ui.cs.advprog.papikos.auth.dto.*;
import id.ac.ui.cs.advprog.papikos.auth.response.ApiResponse;
import id.ac.ui.cs.advprog.papikos.auth.service.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Healthcheck endpoint.
     *
     * @return ResponseEntity with ApiResponse containing "OK" status and message.
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> healthCheck() {
        ApiResponse<String> response = ApiResponse.<String>builder()
                .status(HttpStatus.OK)
                .message("Service is healthy")
                .data("OK")
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Registers a new tenant.
     *
     * @param request The registration request.
     * @return ResponseEntity with ApiResponse containing the created UserDto.
     */
    @PostMapping("/tenant/new")
    public ResponseEntity<ApiResponse<UserDto>> registerTenant(@RequestBody RegisterUserRequest request) {
        UserDto userDto = authenticationService.registerTenant(request);
        ApiResponse<UserDto> response = ApiResponse.<UserDto>builder()
                .status(HttpStatus.CREATED)
                .message("Tenant registered successfully")
                .data(userDto)
                .build();
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Registers a new owner.
     *
     * @param request The registration request.
     * @return ResponseEntity with ApiResponse containing the created UserDto.
     */
    @PostMapping("/owner/new")
    public ResponseEntity<ApiResponse<UserDto>> registerOwner(@RequestBody RegisterUserRequest request) {
        UserDto userDto = authenticationService.registerOwner(request);
        ApiResponse<UserDto> response = ApiResponse.<UserDto>builder()
                .status(HttpStatus.CREATED)
                .message("Owner registered successfully, pending approval")
                .data(userDto)
                .build();
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Logs in a user or admin.
     *
     * @param request The login request.
     * @return ResponseEntity with ApiResponse containing the LoginResponse.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest request) {
        LoginResponse loginResponse = authenticationService.login(request);
        ApiResponse<LoginResponse> response = ApiResponse.<LoginResponse>builder()
                .status(HttpStatus.OK)
                .message("Login successful")
                .data(loginResponse)
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Logs out the currently authenticated user.
     *
     * @return ResponseEntity with ApiResponse indicating successful logout.
     */
    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Object>> logout() {
        authenticationService.logout();
        ApiResponse<Object> response = ApiResponse.<Object>builder()
                .status(HttpStatus.OK)
                .message("Logout successful")
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Approves an owner registration. Requires ADMIN role.
     *
     * @param userId The UUID of the owner to approve.
     * @return ResponseEntity with ApiResponse containing the updated UserDto.
     */
    @PatchMapping("/owner/{userId}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserDto>> approveOwner(@PathVariable UUID userId) {
        UserDto updatedUser = authenticationService.approveOwner(userId);
        ApiResponse<UserDto> response = ApiResponse.<UserDto>builder()
                .status(HttpStatus.OK)
                .message("Owner approved successfully")
                .data(updatedUser)
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Gets the details of the currently authenticated user.
     *
     * @return ResponseEntity with ApiResponse containing the UserDto.
     */
    @GetMapping("/user/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserDto>> getCurrentUser() {
        UserDto userDto = authenticationService.getCurrentUser();
        ApiResponse<UserDto> response = ApiResponse.<UserDto>builder()
                .status(HttpStatus.OK)
                .message("Current user details fetched successfully")
                .data(userDto)
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Gets a list of owners pending approval. Requires ADMIN role.
     *
     * @return ResponseEntity with ApiResponse containing a list of UserDto.
     */
    @GetMapping("/owner/pending")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserDto>>> getPendingOwners() {
        List<UserDto> pendingOwners = authenticationService.getPendingOwners();
        ApiResponse<List<UserDto>> response = ApiResponse.<List<UserDto>>builder()
                .status(HttpStatus.OK)
                .message("Pending owners fetched successfully")
                .data(pendingOwners)
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Verifies an authentication token provided in a custom header.
     * This endpoint is intended for internal service-to-service communication.
     *
     * @return ResponseEntity with ApiResponse indicating token validity.
     */
    @PostMapping("/verify")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Object>> verifyInternalToken() {
        ApiResponse<Object> response = ApiResponse.builder()
                .status(HttpStatus.OK)
                .message("Token is valid")
                .build();
        return ResponseEntity.ok(response);
    }

    // Internal Endpoints

    /**
     * Retrieves a user by ID for internal services.
     *
     * @param userId The UUID of the user.
     * @return ResponseEntity with ApiResponse containing the UserDto.
     */
    @GetMapping("/user/{userId}/internal")
    public ResponseEntity<ApiResponse<UserDto>> getInternalUserById(@PathVariable UUID userId) {
        UserDto userDto = authenticationService.getInternalUserById(userId);
        ApiResponse<UserDto> response = ApiResponse.<UserDto>builder()
                .status(HttpStatus.OK)
                .message("Internal user details fetched successfully")
                .data(userDto)
                .build();
        return ResponseEntity.ok(response);
    }

    /**
     * Retrieves multiple users by a comma-separated list of IDs for internal services.
     *
     * @param ids A comma-separated string of user UUIDs.
     * @return ResponseEntity with ApiResponse containing a list of UserDto.
     */
    @GetMapping("/user/internal")
    public ResponseEntity<ApiResponse<List<UserDto>>> getInternalUsersByIds(@RequestParam String ids) {
        List<UserDto> users = authenticationService.getInternalUsersByIds(ids);
        ApiResponse<List<UserDto>> response = ApiResponse.<List<UserDto>>builder()
                .status(HttpStatus.OK)
                .message("Internal users details fetched successfully")
                .data(users)
                .build();
        return ResponseEntity.ok(response);
    }
}