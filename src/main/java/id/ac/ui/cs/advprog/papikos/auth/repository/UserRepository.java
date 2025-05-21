package id.ac.ui.cs.advprog.papikos.auth.repository;

import id.ac.ui.cs.advprog.papikos.auth.model.Role;
import id.ac.ui.cs.advprog.papikos.auth.model.User;
import id.ac.ui.cs.advprog.papikos.auth.model.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
    Boolean existsByEmail(String email);
    List<User> findAllByStatus(UserStatus status);
    List<User> findAllByRoleAndStatus(Role role, UserStatus status);
    List<User> findAllByUserIdIn(List<UUID> ids);
} 