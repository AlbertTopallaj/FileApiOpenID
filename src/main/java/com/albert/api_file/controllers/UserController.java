package com.albert.api_file.controllers;

import com.albert.api_file.dtos.*;
import com.albert.api_file.models.User;
import com.albert.api_file.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> createUser(@RequestBody RegisterUserRequest request) {
        var user = userService.createUser(request.getUsername(), request.getPassword());
        return ResponseEntity.created(URI.create("/user")).body(UserResponse.fromModel(user));
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
        String token = userService.login(loginRequest.getUsername(), loginRequest.getPassword());
        return ResponseEntity.ok(new LoginResponse(token));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUserById(@PathVariable UUID userId) {
        return userService
                .getUserById(userId)
                .map(user -> ResponseEntity.ok(UserResponse.fromModel(user)))
                .orElse(ResponseEntity.notFound().build());
    }
}

