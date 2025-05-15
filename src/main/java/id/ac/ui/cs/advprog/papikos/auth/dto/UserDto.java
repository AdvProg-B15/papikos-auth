package id.ac.ui.cs.advprog.papikos.auth.dto;

import id.ac.ui.cs.advprog.papikos.auth.model.Role;
import id.ac.ui.cs.advprog.papikos.auth.model.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private Long userId;
    private String email;
    private Role role;
    private UserStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
} 