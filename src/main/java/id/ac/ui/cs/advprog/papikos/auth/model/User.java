package id.ac.ui.cs.advprog.papikos.auth.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String passwordHash; // Store hashed password

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role; // Enum: TENANT, OWNER, ADMIN

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status; // Enum: PENDING_APPROVAL, ACTIVE, INACTIVE

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;
}
