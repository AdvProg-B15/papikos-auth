package id.ac.ui.cs.advprog.papikos.auth.service;

import id.ac.ui.cs.advprog.papikos.auth.dto.*;
import id.ac.ui.cs.advprog.papikos.auth.exception.BadRequestException;
import id.ac.ui.cs.advprog.papikos.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.papikos.auth.exception.ResourceNotFoundException;
import id.ac.ui.cs.advprog.papikos.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.papikos.auth.model.Role;
import id.ac.ui.cs.advprog.papikos.auth.model.User;
import id.ac.ui.cs.advprog.papikos.auth.model.UserStatus;
import id.ac.ui.cs.advprog.papikos.auth.repository.UserRepository;
import id.ac.ui.cs.advprog.papikos.auth.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Transactional
    public UserDto registerTenant(RegisterUserRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ConflictException("Email is already taken!");
        }

        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.TENANT)
                .status(UserStatus.ACTIVE)
                .build();
        userRepository.save(user);
        return mapToUserDto(user);
    }

    @Transactional
    public UserDto registerOwner(RegisterUserRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ConflictException("Email is already taken!");
        }

        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.OWNER)
                .status(UserStatus.PENDING_APPROVAL)
                .build();
        userRepository.save(user);
        return mapToUserDto(user);
    }

    public LoginResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtTokenProvider.generateToken(authentication);
        
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + request.getEmail()));

        return new LoginResponse(jwt, "Bearer", mapToUserDto(user));
    }

    // Logout: JWTs are stateless. Client should discard the token.
    // For blacklist-based logout, you'd need a JwtBlacklistService and store invalidated tokens.
    public void logout() {
        // If implementing blacklist, add current token to blacklist here.
        SecurityContextHolder.clearContext();
    }

    @Transactional
    public UserDto approveOwner(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("Owner not found with id: " + userId));

        if (user.getRole() != Role.OWNER || user.getStatus() != UserStatus.PENDING_APPROVAL) {
            throw new BadRequestException("User is not a pending owner or not an owner.");
        }
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);
        return mapToUserDto(user);
    }

    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal().equals("anonymousUser")) {
            throw new UnauthorizedException("User not authenticated or token is invalid.");
        }
        String email;
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            email = ((UserDetails) principal).getUsername();
        } else {
            email = principal.toString(); // Should ideally not happen if JWT filter and UserDetailsService work correctly
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
        return mapToUserDto(user);
    }

    public List<UserDto> getPendingOwners() {
        return userRepository.findAllByStatus(UserStatus.PENDING_APPROVAL).stream()
                .map(this::mapToUserDto)
                .collect(Collectors.toList());
    }

    public UserDto getInternalUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
        return mapToUserDto(user);
    }

    public List<UserDto> getInternalUsersByIds(String ids) {
        List<Long> userIdList = Arrays.stream(ids.split(","))
                .map(String::trim)
                .map(Long::parseLong)
                .collect(Collectors.toList());
        return userRepository.findAllByUserIdIn(userIdList).stream()
                .map(this::mapToUserDto)
                .collect(Collectors.toList());
    }

    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .role(user.getRole())
                .status(user.getStatus())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
} 