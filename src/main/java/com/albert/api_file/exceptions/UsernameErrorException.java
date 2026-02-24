package com.albert.api_file.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UsernameErrorException extends RuntimeException {

    public UsernameErrorException(String message) {
        super(message);
    }

    public UsernameErrorException() {
        super("Username is missing or its shorter than 4 characters");
    }
}
