package id.ac.ui.cs.advprog.papikos.auth.security;

import id.ac.ui.cs.advprog.papikos.auth.model.User;
import id.ac.ui.cs.advprog.papikos.auth.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID; // Import UUID

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }
        User user = userOptional.get();
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPasswordHash(),
                getAuthorities(user));
    }

    /**
     * Loads a user by their ID. This is a helper method and not an override from UserDetailsService.
     *
     * @param id The UUID of the user.
     * @return UserDetails object for the found user.
     * @throws UsernameNotFoundException if the user is not found.
     */
    public UserDetails loadUserById(UUID id) { // Changed parameter type to UUID
        Optional<User> userOptional = userRepository.findById(id); // Assuming userRepository.findById() now accepts UUID
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with id: " + id);
        }
        User user = userOptional.get();
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPasswordHash(),
                getAuthorities(user));
    }

    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }
}