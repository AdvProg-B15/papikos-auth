package id.ac.ui.cs.advprog.papikos.auth.service;

import id.ac.ui.cs.advprog.papikos.auth.dto.LoginRequest;
import id.ac.ui.cs.advprog.papikos.auth.dto.LoginResponse;
import id.ac.ui.cs.advprog.papikos.auth.dto.RegisterUserRequest;
import id.ac.ui.cs.advprog.papikos.auth.dto.UserDto;
import id.ac.ui.cs.advprog.papikos.auth.model.Role;
import id.ac.ui.cs.advprog.papikos.auth.model.User;
import id.ac.ui.cs.advprog.papikos.auth.model.UserStatus;
import id.ac.ui.cs.advprog.papikos.auth.repository.UserRepository;
import id.ac.ui.cs.advprog.papikos.auth.security.JwtTokenProvider; // Import JwtTokenProvider
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.Arrays;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider; // Inject JwtTokenProvider

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    public AuthenticationService(UserRepository userRepository,
                                 PasswordEncoder passwordEncoder,
                                 AuthenticationManager authenticationManager,
                                 JwtTokenProvider jwtTokenProvider) { // Add to constructor
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider; // Initialize
    }

    @Transactional
    public UserDto registerTenant(RegisterUserRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.TENANT)
                .status(UserStatus.ACTIVE)
                .build();
        user = userRepository.save(user);
        return mapToUserDto(user);
    }

    @Transactional
    public UserDto registerOwner(RegisterUserRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.OWNER)
                .status(UserStatus.PENDING_APPROVAL)
                .build();
        user = userRepository.save(user);
        return mapToUserDto(user);
    }

    public LoginResponse login(LoginRequest request) {
        // Admin login check
        if (request.getEmail().equals(adminEmail) && request.getPassword().equals(adminPassword)) {
            UserDetails adminDetails = new org.springframework.security.core.userdetails.User(
                    adminEmail,
                    "", // Password not needed for token generation here
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + Role.ADMIN.name()))
            );
            // Admin does not have a UUID in the User table, so pass null for userId
            String token = jwtTokenProvider.generateToken(adminDetails, null);
            UserDto adminDto = UserDto.builder()
                                .email(adminEmail)
                                .role(Role.ADMIN)
                                .status(UserStatus.ACTIVE)
                                .build();
            return new LoginResponse(token, "Bearer", adminDto);
        }

        // Regular user login
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found after authentication: " + userDetails.getUsername()));

        String token = jwtTokenProvider.generateToken(userDetails, user.getUserId());
        return new LoginResponse(token, "Bearer", mapToUserDto(user));
    }

    public void logout() {
        SecurityContextHolder.clearContext();
    }

    @Transactional
    public UserDto approveOwner(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        if (user.getRole() != Role.OWNER) {
            throw new IllegalArgumentException("User is not an owner.");
        }
        user.setStatus(UserStatus.ACTIVE);
        user = userRepository.save(user);
        return mapToUserDto(user);
    }

    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
             throw new RuntimeException("No authenticated user found");
        }
        String currentUsername = authentication.getName();

        if (currentUsername.equals(adminEmail)) {
             // Check if the principal's authorities match ADMIN role for safety
            boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_" + Role.ADMIN.name()));
            if (isAdmin) {
                return UserDto.builder()
                    .email(adminEmail)
                    .role(Role.ADMIN)
                    .status(UserStatus.ACTIVE)
                    .build();
            }
        }
        User user = userRepository.findByEmail(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found: " + currentUsername));
        return mapToUserDto(user);
    }

    public List<UserDto> getPendingOwners() {
        return userRepository.findAllByRoleAndStatus(Role.OWNER, UserStatus.PENDING_APPROVAL)
                .stream()
                .map(this::mapToUserDto)
                .collect(Collectors.toList());
    }

    public UserDto getInternalUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        return mapToUserDto(user);
    }

    public List<UserDto> getInternalUsersByIds(String ids) {
        List<UUID> uuidList = Arrays.stream(ids.split(","))
                                .map(String::trim)
                                .map(UUID::fromString)
                                .collect(Collectors.toList());
        return userRepository.findAllById(uuidList)
                .stream()
                .map(this::mapToUserDto)
                .collect(Collectors.toList());
    }

    public boolean verifyToken(String token) {
        return jwtTokenProvider.validateToken(token); // Use JwtTokenProvider for validation
    }

    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .role(user.getRole())
                .status(user.getStatus())
                .build();
    }
}