package com.albert.api_file.handlers;

import com.albert.api_file.exceptions.*;
import com.albert.api_file.utilites.DateFormatterUtility;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private ResponseEntity<Object> buildResponse(RuntimeException e, HttpStatus httpStatus) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now().format(DateFormatterUtility.DATE_TIME_FORMATTER));
        body.put("status", httpStatus.value());
        body.put("error", httpStatus.getReasonPhrase());
        body.put("message", e.getMessage());
        return new ResponseEntity<>(body, httpStatus);
    }

    @ExceptionHandler(FileNotFoundException.class)
    public ResponseEntity<Object> handleFileNotFound(FileNotFoundException e) {
        return buildResponse(e, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(FileIsEmptyException.class)
    public ResponseEntity<Object> handleFileIsEmpty(FileIsEmptyException e) {
        return buildResponse(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(FileDoesntExistException.class)
    public ResponseEntity<Object> handleFileDoesntExist(FileDoesntExistException e) {
        return buildResponse(e, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MissingFileNameException.class)
    public ResponseEntity<Object> handleMissingFileName(MissingFileNameException e) {
        return buildResponse(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MissingFolderNameException.class)
    public ResponseEntity<Object> handleMissingFolderName(MissingFolderNameException e) {
        return buildResponse(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<Object> handleUserAlreadyExists(UserAlreadyExistsException e) {
        return buildResponse(e, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(UsernameErrorException.class)
    public ResponseEntity<Object> handleUsernameError(UsernameErrorException e) {
        return buildResponse(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(PasswordErrorException.class)
    public ResponseEntity<Object> handlePasswordError(PasswordErrorException e) {
        return buildResponse(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidUserCredentialsException.class)
    public ResponseEntity<Object> handleInvalidCredentials(InvalidUserCredentialsException e) {
        return buildResponse(e, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(DatabaseException.class)
    public ResponseEntity<Object> handleDatabase(DatabaseException e) {
        return buildResponse(e, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleAll(Exception e) {
        return buildResponse(new RuntimeException(e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

