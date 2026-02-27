package com.albert.api_file.security;


import com.albert.api_file.repositories.IUserRepository;
import com.albert.api_file.services.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            JWTService jwtService,
            UserService userService,
            OAuth2SuccessHandler oauth2SuccessHandler
    ) {
        http.csrf(AbstractHttpConfigurer::disable)
                .userDetailsService(userService)
                .oauth2Login(oauth ->
                        oauth.successHandler(oauth2SuccessHandler)
                )
                .authorizeHttpRequests(auth -> {
                    auth
                            .requestMatchers("/register").permitAll()
                            .requestMatchers("/login").permitAll()
                            .anyRequest().authenticated();
                })
                .addFilterBefore(
                        new AuthenticationFilter(jwtService, userService),
                        OAuth2LoginAuthenticationFilter.class
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
