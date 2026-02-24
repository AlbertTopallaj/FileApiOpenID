package com.albert.api_file.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class FileAlreadyExistsException extends RuntimeException {

    public FileAlreadyExistsException(String message) {
        super(message);
    }

    public FileAlreadyExistsException() {
        super("The file already exists");
    }
}
