package com.albert.api_file.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class FolderDoesntExistException extends RuntimeException {

    public FolderDoesntExistException(String message) {
        super(message);
    }

    public FolderDoesntExistException() {
        super("The folder does not exist");
    }
}
