package id.ac.ui.cs.advprog.papikos.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtTokenProvider tokenProvider;

    private final CustomUserDetailsService customUserDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider,
                                   CustomUserDetailsService customUserDetailsService) {
        this.tokenProvider = tokenProvider;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                UUID userId = tokenProvider.getUserIdFromJWT(jwt);
                String email = tokenProvider.getEmailFromJWT(jwt);
                List<SimpleGrantedAuthority> authorities = tokenProvider.getRolesFromJWT(jwt);

                UserDetails userDetails;

                if (userId != null) { // Regular user token with UUID in subject
                    try {
                        userDetails = customUserDetailsService.loadUserById(userId);
                        // Optional: Verify if email from token matches email from loaded UserDetails for consistency
                        if (!email.equals(userDetails.getUsername())) {
                            logger.warn("Email mismatch between JWT ({}) and loaded UserDetails ({}) for userId {}", email, userDetails.getUsername(), userId);
                            // Decide handling: proceed, or reject if strict matching is required
                        }
                    } catch (UsernameNotFoundException ex) {
                        logger.error("User ID {} from JWT not found in database.", userId, ex);
                        SecurityContextHolder.clearContext();
                        filterChain.doFilter(request, response);
                        return;
                    }
                } else { // Subject is not a UUID, potentially an admin token (subject is email)
                    boolean isAdminByRole = authorities.stream()
                            .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
                    // Ensure email is present and matches the subject if it's an admin token
                    String subject = tokenProvider.getSubjectFromJWT(jwt);
                    if (isAdminByRole && email != null && email.equals(subject)) {
                        userDetails = new org.springframework.security.core.userdetails.User(
                                email, "", authorities);
                    } else {
                        logger.warn("JWT subject '{}' is not a UUID and not identified as a valid admin token.", subject);
                        SecurityContextHolder.clearContext();
                        filterChain.doFilter(request, response);
                        return;
                    }
                }

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
            SecurityContextHolder.clearContext(); // Ensure context is cleared on error
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}