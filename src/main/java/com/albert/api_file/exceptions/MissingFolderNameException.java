package com.albert.api_file.exceptions;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class MissingFolderNameException extends RuntimeException {

    public MissingFolderNameException(String message) {
        super(message);
    }

    public MissingFolderNameException() {
        super("The folder name is missing");
    }
}
