package id.ac.ui.cs.advprog.papikos.auth.security;

import id.ac.ui.cs.advprog.papikos.auth.model.Role; // Keep if needed for other logic, not directly used in generateToken
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    private Key getSigningKey() {
        // IMPORTANT: For HS512, the secret key should be at least 64 bytes long.
        // Ensure 'app.jwtSecret' in your properties is sufficiently long and secure.
        byte[] keyBytes = jwtSecret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generates a JWT for the given user details.
     * @param userDetails The Spring Security UserDetails of the authenticated user.
     * @param userId The UUID of the user. Can be null (e.g., for an admin not stored in User table).
     * @return A JWT string.
     */
    public String generateToken(UserDetails userDetails, UUID userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        String subject = (userId != null) ? userId.toString() : userDetails.getUsername(); // Use email as subject if userId is null

        String roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(subject)
                .claim("email", userDetails.getUsername())
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Extracts the user ID (UUID) from the JWT subject claim.
     * @param token The JWT string.
     * @return The UUID of the user, or null if the subject is not a valid UUID.
     */
    public UUID getUserIdFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        try {
            return UUID.fromString(claims.getSubject());
        } catch (IllegalArgumentException e) {
            return null; // Subject is not a UUID (e.g., admin email)
        }
    }

    /**
     * Extracts the email from the JWT "email" claim.
     * @param token The JWT string.
     * @return The email address.
     */
    public String getEmailFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("email", String.class);
    }

    /**
     * Extracts roles from the JWT "roles" claim.
     * @param token The JWT string.
     * @return A list of SimpleGrantedAuthority.
     */
    public List<SimpleGrantedAuthority> getRolesFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        String rolesClaim = claims.get("roles", String.class);
        if (rolesClaim == null || rolesClaim.isEmpty()) {
            return List.of();
        }
        return Arrays.stream(rolesClaim.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Extracts the subject from the JWT.
     * @param token The JWT string.
     * @return The subject string.
     */
    public String getSubjectFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }


    /**
     * Validates the integrity and expiration of the JWT.
     * @param authToken The JWT string.
     * @return true if the token is valid, false otherwise.
     */
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            // logger.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            // logger.error("JWT token is expired: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            // logger.error("JWT token is unsupported: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            // logger.error("JWT claims string is empty: {}", ex.getMessage());
        }
        return false;
    }
}
