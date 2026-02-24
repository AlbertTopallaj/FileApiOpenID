package com.albert.api_file.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class PasswordErrorException extends RuntimeException {

    public PasswordErrorException(String message) {
        super(message);
    }

    public PasswordErrorException() {
        super("Password is missing or its shorter than 8 characters");
    }
}
