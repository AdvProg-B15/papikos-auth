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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private AuthenticationService authenticationService;

    private User tenantUser;
    private User ownerUser;
    private User adminUser;
    private RegisterUserRequest registerUserRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        registerUserRequest = new RegisterUserRequest("test@example.com", "password");
        loginRequest = new LoginRequest("test@example.com", "password");

        tenantUser = User.builder()
                .userId(1L)
                .email("tenant@example.com")
                .passwordHash("hashedPassword")
                .role(Role.TENANT)
                .status(UserStatus.ACTIVE)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        ownerUser = User.builder()
                .userId(2L)
                .email("owner@example.com")
                .passwordHash("hashedPassword")
                .role(Role.OWNER)
                .status(UserStatus.PENDING_APPROVAL)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        
        adminUser = User.builder()
                .userId(3L)
                .email("admin@example.com")
                .passwordHash("hashedPassword")
                .role(Role.ADMIN)
                .status(UserStatus.ACTIVE)
                .build();
    }

    @Test
    void registerTenant_Success() {
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserDto result = authenticationService.registerTenant(registerUserRequest);

        assertNotNull(result);
        assertEquals(registerUserRequest.getEmail(), result.getEmail());
        assertEquals(Role.TENANT, result.getRole());
        assertEquals(UserStatus.ACTIVE, result.getStatus());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void registerTenant_EmailConflict() {
        when(userRepository.existsByEmail(anyString())).thenReturn(true);
        assertThrows(ConflictException.class, () -> authenticationService.registerTenant(registerUserRequest));
    }

    @Test
    void registerOwner_Success() {
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserDto result = authenticationService.registerOwner(registerUserRequest);

        assertNotNull(result);
        assertEquals(registerUserRequest.getEmail(), result.getEmail());
        assertEquals(Role.OWNER, result.getRole());
        assertEquals(UserStatus.PENDING_APPROVAL, result.getStatus());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void registerOwner_EmailConflict() {
        when(userRepository.existsByEmail(anyString())).thenReturn(true);
        assertThrows(ConflictException.class, () -> authenticationService.registerOwner(registerUserRequest));
    }

    @Test
    void login_Success() {
        // Arrange
        Authentication successfulAuthentication = mock(Authentication.class); // This is what manager.authenticate returns
        UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))) // Use any() or specific matcher
                .thenReturn(successfulAuthentication);

        when(jwtTokenProvider.generateToken(successfulAuthentication)).thenReturn("jwtToken");
        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(tenantUser));

        // Mock SecurityContext
        SecurityContext securityContext = mock(SecurityContext.class);
        SecurityContext originalContext = SecurityContextHolder.getContext(); // Store original context
        SecurityContextHolder.setContext(securityContext); // Set the mocked context

        // Act
        LoginResponse result = authenticationService.login(loginRequest);

        // Assert
        assertNotNull(result);
        assertEquals("jwtToken", result.getAccessToken());
        assertEquals(tenantUser.getEmail(), result.getUser().getEmail());
        
        // Verify that setAuthentication was called on our mocked SecurityContext
        verify(securityContext).setAuthentication(successfulAuthentication);

        // Clean up: restore original context
        SecurityContextHolder.setContext(originalContext);
    }

    @Test
    void login_UserNotFoundAfterAuth() {
        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> authenticationService.login(loginRequest));
    }
    
    @Test
    void login_BadCredentials() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenThrow(new BadCredentialsException("Bad credentials"));
        assertThrows(BadCredentialsException.class, () -> authenticationService.login(loginRequest));
    }

    @Test
    void logout_ClearsSecurityContext() {
        // To ensure context is not null before clearing
        SecurityContextHolder.getContext().setAuthentication(mock(Authentication.class)); 
        authenticationService.logout();
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void approveOwner_Success() {
        when(userRepository.findById(ownerUser.getUserId())).thenReturn(Optional.of(ownerUser));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserDto result = authenticationService.approveOwner(ownerUser.getUserId());

        assertNotNull(result);
        assertEquals(UserStatus.ACTIVE, result.getStatus());
        verify(userRepository).save(ownerUser);
    }

    @Test
    void approveOwner_NotFound() {
        when(userRepository.findById(anyLong())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> authenticationService.approveOwner(1L));
    }

    @Test
    void approveOwner_NotOwner() {
        when(userRepository.findById(tenantUser.getUserId())).thenReturn(Optional.of(tenantUser)); // tenantUser is not an OWNER
        assertThrows(BadRequestException.class, () -> authenticationService.approveOwner(tenantUser.getUserId()));
    }

    @Test
    void approveOwner_NotPendingApproval() {
        ownerUser.setStatus(UserStatus.ACTIVE); // Change status to not PENDING_APPROVAL
        when(userRepository.findById(ownerUser.getUserId())).thenReturn(Optional.of(ownerUser));
        assertThrows(BadRequestException.class, () -> authenticationService.approveOwner(ownerUser.getUserId()));
    }

    @Test
    void getCurrentUser_Success() {
        Authentication authentication = mock(Authentication.class);
        UserDetails userDetails = mock(UserDetails.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(tenantUser.getEmail());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(userRepository.findByEmail(tenantUser.getEmail())).thenReturn(Optional.of(tenantUser));

        UserDto result = authenticationService.getCurrentUser();

        assertNotNull(result);
        assertEquals(tenantUser.getEmail(), result.getEmail());
    }

    @Test
    void getCurrentUser_NotAuthenticated() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertThrows(UnauthorizedException.class, () -> authenticationService.getCurrentUser());
    }
    
    @Test
    void getCurrentUser_PrincipalAnonymous() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn("anonymousUser");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertThrows(UnauthorizedException.class, () -> authenticationService.getCurrentUser());
    }

    @Test
    void getCurrentUser_UserNotFoundFromPrincipal() {
        Authentication authentication = mock(Authentication.class);
        UserDetails userDetails = mock(UserDetails.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("unknown@example.com");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> authenticationService.getCurrentUser());
    }

    @Test
    void getPendingOwners_Success() {
        when(userRepository.findAllByStatus(UserStatus.PENDING_APPROVAL)).thenReturn(Collections.singletonList(ownerUser));
        List<UserDto> result = authenticationService.getPendingOwners();
        assertFalse(result.isEmpty());
        assertEquals(1, result.size());
        assertEquals(ownerUser.getEmail(), result.get(0).getEmail());
    }

    @Test
    void getPendingOwners_EmptyList() {
        when(userRepository.findAllByStatus(UserStatus.PENDING_APPROVAL)).thenReturn(Collections.emptyList());
        List<UserDto> result = authenticationService.getPendingOwners();
        assertTrue(result.isEmpty());
    }

    @Test
    void getInternalUserById_Success() {
        when(userRepository.findById(tenantUser.getUserId())).thenReturn(Optional.of(tenantUser));
        UserDto result = authenticationService.getInternalUserById(tenantUser.getUserId());
        assertNotNull(result);
        assertEquals(tenantUser.getEmail(), result.getEmail());
    }

    @Test
    void getInternalUserById_NotFound() {
        when(userRepository.findById(anyLong())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> authenticationService.getInternalUserById(1L));
    }

    @Test
    void getInternalUsersByIds_Success() {
        List<User> users = Arrays.asList(tenantUser, ownerUser);
        List<Long> ids = Arrays.asList(tenantUser.getUserId(), ownerUser.getUserId());
        when(userRepository.findAllByUserIdIn(ids)).thenReturn(users);

        List<UserDto> result = authenticationService.getInternalUsersByIds("1,2");

        assertFalse(result.isEmpty());
        assertEquals(2, result.size());
        assertTrue(result.stream().anyMatch(dto -> dto.getEmail().equals(tenantUser.getEmail())));
        assertTrue(result.stream().anyMatch(dto -> dto.getEmail().equals(ownerUser.getEmail())));
    }
    
    @Test
    void getInternalUsersByIds_SingleId_Success() {
        when(userRepository.findAllByUserIdIn(Collections.singletonList(tenantUser.getUserId()))).thenReturn(Collections.singletonList(tenantUser));
        List<UserDto> result = authenticationService.getInternalUsersByIds(tenantUser.getUserId().toString());
        assertEquals(1, result.size());
        assertEquals(tenantUser.getEmail(), result.get(0).getEmail());
    }

    @Test
    void getInternalUsersByIds_NonExistentIds() {
        when(userRepository.findAllByUserIdIn(anyList())).thenReturn(Collections.emptyList());
        List<UserDto> result = authenticationService.getInternalUsersByIds("99,100");
        assertTrue(result.isEmpty());
    }
} 