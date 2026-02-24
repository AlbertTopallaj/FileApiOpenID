package com.albert.api_file.exceptions;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class MissingFileNameException extends RuntimeException {

    public MissingFileNameException(String message) {
        super(message);
    }

    public MissingFileNameException() {
        super("File name is missing");
    }

}
