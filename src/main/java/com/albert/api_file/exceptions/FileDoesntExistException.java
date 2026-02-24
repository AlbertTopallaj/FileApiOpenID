package com.albert.api_file.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class FileDoesntExistException extends RuntimeException {

    public FileDoesntExistException(String message) {
        super(message);
    }

    public FileDoesntExistException() {
        super("The file does not exist");
    }
}
