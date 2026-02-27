package com.albert.api_file.security;

import com.albert.api_file.models.User;
import com.albert.api_file.services.UserService;
import jakarta.annotation.Nullable;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final JWTService jwtService;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final WebClient webClient = WebClient
            .builder()
            .baseUrl("https://api.github.com")
            .build();

    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) throws IOException {
        var oauth2Token = (OAuth2AuthenticationToken) authentication;

        var oidcProvider = oauth2Token.getAuthorizedClientRegistrationId();
        var oidcId = oauth2Token.getName();

        System.out.println("Provider: " + oidcProvider);
        System.out.println("Id: " + oidcId);

        var user = userService.getUserByOidc(oidcId, oidcProvider);
        System.out.println("User exists: " + user.isPresent());
        if (user.isEmpty()) {
            var createdUser = createUser(oidcId, oidcProvider, request, authentication);
            if (createdUser == null) {
                response.getWriter().println("Failed to create account");
            } else {
                var token = jwtService.generateToken(createdUser.getId());
                response.getWriter().println("Registered account: " + createdUser.getUsername());
                response.getWriter().println("token: " + token);
            }
        } else {
            var token = jwtService.generateToken(user.get().getId());
            response.getWriter().println("Logged in as: " + user.get().getUsername());
            response.getWriter().println("token: " + token);
        }
    }

    @Nullable
    private User createUser(
            String oidcId,
            String oidcProvider,
            HttpServletRequest request,
            Authentication authentication
    ) {
        var authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                oidcProvider,
                authentication,
                request
        );

        if (authorizedClient == null){
            return null;
        }

        var accessToken = authorizedClient.getAccessToken().getTokenValue();

        var emailResponse = webClient
                .get()
                .uri("/user/emails")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .toEntity(new ParameterizedTypeReference<List<GetEmailsResponse>>() {
                })
                .block();

        if (emailResponse == null) {
            return null;
        }

        if (emailResponse.getStatusCode() != HttpStatus.OK) {
            return null;
        }

        var emails = emailResponse.getBody();
        if (emails == null || emails.isEmpty()) {
            return null;
        }

        var email = emails.getFirst();

        return userService.createOidcUser(email.getEmail(), oidcId, oidcProvider);
    }

    @Getter
    @Setter
    private static class GetEmailsResponse {
        private String email;
    }

}
