package com.albert.api_file.services;

import com.albert.api_file.exceptions.InvalidUserCredentialsException;
import com.albert.api_file.exceptions.PasswordErrorException;
import com.albert.api_file.exceptions.UserAlreadyExistsException;
import com.albert.api_file.exceptions.UsernameErrorException;
import com.albert.api_file.models.User;
import com.albert.api_file.repositories.IUserRepository;
import com.albert.api_file.security.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final IUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;

    /**
     * Creates a user with the information username and password given by the user
     *
     * @param username the username that the user inserts
     * @param password the password that the user inserts
     * @return the created user with the information inserted by the user
     * @throws UsernameErrorException if the username is blank or shorter than 4 characters
     * @throws PasswordErrorException if the password is blank or shorter than 8 characters
     * @throws UserAlreadyExistsException if a user with the given username already exists
     */


    public User createUser(String username, String password) {
        if (username.isBlank() || username.length() < 4) {
            throw new UsernameErrorException();
        }

        if (password.isBlank() || password.length() < 8) {
            throw new PasswordErrorException();
        }

        if (userRepository.existsByUsername(username)) {
            throw new UserAlreadyExistsException();
        }

        String hashedPassword = passwordEncoder.encode(password);

        var user = new User(username, hashedPassword);
        user = userRepository.save(user);

        return user;
    }

    /**
     * Login to the system with a username and a password and checks if the user actually exists in the database
     *
     * @param username the username that the user inserts
     * @param password the password that the user inserts
     * @return returns a token with is used to gain access to other endpoints with requires auth
     * @throws InvalidUserCredentialsException if the username does not exist or the password is incorrect
     */

    public String login(String username, String password) {
        Optional<User> optional = userRepository.findByUsername(username);
        if (optional.isEmpty()) {
            throw new InvalidUserCredentialsException();
        }
        User user = optional.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidUserCredentialsException();
        }
        return jwtService.generateToken(user.getId());

    }
}
