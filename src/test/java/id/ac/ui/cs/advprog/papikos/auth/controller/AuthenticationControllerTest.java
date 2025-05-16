package id.ac.ui.cs.advprog.papikos.auth.controller;

import id.ac.ui.cs.advprog.papikos.auth.dto.*;
import id.ac.ui.cs.advprog.papikos.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.papikos.auth.exception.ResourceNotFoundException;
import id.ac.ui.cs.advprog.papikos.auth.model.Role;
import id.ac.ui.cs.advprog.papikos.auth.model.UserStatus;
import id.ac.ui.cs.advprog.papikos.auth.service.AuthenticationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationControllerTest {

    @Mock
    private AuthenticationService authenticationService;

    @InjectMocks
    private AuthenticationController authenticationController;

    private RegisterUserRequest registerUserRequest;
    private LoginRequest loginRequest;
    private UserDto userDtoTenant;
    private UserDto userDtoOwner;
    private LoginResponse loginResponse;

    @BeforeEach
    void setUp() {
        registerUserRequest = new RegisterUserRequest("test@example.com", "password");
        loginRequest = new LoginRequest("test@example.com", "password");

        userDtoTenant = UserDto.builder()
                .userId(1L)
                .email("tenant@example.com")
                .role(Role.TENANT)
                .status(UserStatus.ACTIVE)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        userDtoOwner = UserDto.builder()
                .userId(2L)
                .email("owner@example.com")
                .role(Role.OWNER)
                .status(UserStatus.PENDING_APPROVAL)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        loginResponse = new LoginResponse("jwt-token", "Bearer", userDtoTenant);
    }

    @Test
    void registerTenant_Success() {
        when(authenticationService.registerTenant(any(RegisterUserRequest.class))).thenReturn(userDtoTenant);
        ResponseEntity<UserDto> response = authenticationController.registerTenant(registerUserRequest);
        assertNotNull(response);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(userDtoTenant, response.getBody());
        verify(authenticationService).registerTenant(registerUserRequest);
    }

    @Test
    void registerTenant_Conflict() {
        when(authenticationService.registerTenant(any(RegisterUserRequest.class))).thenThrow(new ConflictException("Email exists"));
        assertThrows(ConflictException.class, () -> authenticationController.registerTenant(registerUserRequest));
    }

    @Test
    void registerOwner_Success() {
        when(authenticationService.registerOwner(any(RegisterUserRequest.class))).thenReturn(userDtoOwner);
        ResponseEntity<UserDto> response = authenticationController.registerOwner(registerUserRequest);
        assertNotNull(response);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(userDtoOwner, response.getBody());
        verify(authenticationService).registerOwner(registerUserRequest);
    }

    @Test
    void login_Success() {
        when(authenticationService.login(any(LoginRequest.class))).thenReturn(loginResponse);
        ResponseEntity<LoginResponse> response = authenticationController.login(loginRequest);
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(loginResponse, response.getBody());
        verify(authenticationService).login(loginRequest);
    }

    @Test
    void login_BadCredentials() {
        when(authenticationService.login(any(LoginRequest.class))).thenThrow(new BadCredentialsException("Bad credentials"));
        assertThrows(BadCredentialsException.class, () -> authenticationController.login(loginRequest));
    }

    @Test
    void logout_Success() {
        doNothing().when(authenticationService).logout();
        ResponseEntity<Void> response = authenticationController.logout();
        assertNotNull(response);
        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(authenticationService).logout();
    }

    @Test
    void approveOwner_Success() {
        UserDto approvedOwnerDto = UserDto.builder().userId(2L).email("owner@example.com").role(Role.OWNER).status(UserStatus.ACTIVE).build();
        when(authenticationService.approveOwner(anyLong())).thenReturn(approvedOwnerDto);
        ResponseEntity<UserDto> response = authenticationController.approveOwner(2L);
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(approvedOwnerDto, response.getBody());
        verify(authenticationService).approveOwner(2L);
    }

    @Test
    void approveOwner_NotFound() {
        when(authenticationService.approveOwner(anyLong())).thenThrow(new ResourceNotFoundException("Not found"));
        assertThrows(ResourceNotFoundException.class, () -> authenticationController.approveOwner(1L));
    }

    @Test
    void getCurrentUser_Success() {
        when(authenticationService.getCurrentUser()).thenReturn(userDtoTenant);
        ResponseEntity<UserDto> response = authenticationController.getCurrentUser();
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userDtoTenant, response.getBody());
        verify(authenticationService).getCurrentUser();
    }

    @Test
    void getPendingOwners_Success() {
        List<UserDto> pendingList = Collections.singletonList(userDtoOwner);
        when(authenticationService.getPendingOwners()).thenReturn(pendingList);
        ResponseEntity<List<UserDto>> response = authenticationController.getPendingOwners();
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(pendingList, response.getBody());
        verify(authenticationService).getPendingOwners();
    }

    @Test
    void getInternalUserById_Success() {
        when(authenticationService.getInternalUserById(anyLong())).thenReturn(userDtoTenant);
        ResponseEntity<UserDto> response = authenticationController.getInternalUserById(1L);
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userDtoTenant, response.getBody());
        verify(authenticationService).getInternalUserById(1L);
    }

    @Test
    void getInternalUserById_NotFound() {
        when(authenticationService.getInternalUserById(anyLong())).thenThrow(new ResourceNotFoundException("Not found"));
        assertThrows(ResourceNotFoundException.class, () -> authenticationController.getInternalUserById(99L));
    }

    @Test
    void getInternalUsersByIds_Success() {
        List<UserDto> userList = Collections.singletonList(userDtoTenant);
        when(authenticationService.getInternalUsersByIds(anyString())).thenReturn(userList);
        ResponseEntity<List<UserDto>> response = authenticationController.getInternalUsersByIds("1");
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(userList, response.getBody());
        verify(authenticationService).getInternalUsersByIds("1");
    }
}