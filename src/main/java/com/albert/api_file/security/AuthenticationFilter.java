package com.albert.api_file.security;

import com.albert.api_file.models.User;
import com.albert.api_file.repositories.IUserRepository;
import com.albert.api_file.services.UserService;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;

@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final IUserRepository userRepository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String authenticationHeader = request.getHeader("Authorization");
        if (authenticationHeader == null || authenticationHeader.isBlank() || authenticationHeader.length() <= "Bearer ".length()) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken = authenticationHeader.substring("Bearer ".length());

        UUID userId;
        try {
            userId = jwtService.verifyToken(jwtToken);
        } catch (JWTVerificationException exception) {
            response.setStatus(401);
            return;
        }

        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isEmpty()) {
            response.setStatus(401);
            return;
        }

        User user = userOptional.get();

        SecurityContextHolder
                .getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(
                        user, user.getPassword(), new ArrayList<>()
                ));
        filterChain.doFilter(request, response);
    }
}
