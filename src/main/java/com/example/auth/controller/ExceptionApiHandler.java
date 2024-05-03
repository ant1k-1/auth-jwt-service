package com.example.auth.controller;

import com.example.auth.exception.AuthException;
import com.example.auth.exception.ErrorMessage;
import com.example.auth.exception.NotFoundException;
import com.google.gson.Gson;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionApiHandler {

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorMessage> notFoundException(NotFoundException ex) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ErrorMessage(
                        HttpStatus.NOT_FOUND.value(),
                        HttpStatus.NOT_FOUND.name(),
                        ex.getMessage())
                );
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorMessage> authException(AuthException ex) {
//        Gson gson = new Gson();
        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(new ErrorMessage(
                        ex.getHttpStatus().value(),
                        ex.getAuthStatus().name(),
                        ex.getMessage()
                ));

//        return ResponseEntity
//                .status(HttpStatus.UNAUTHORIZED)
//                .body(new ErrorMessage(exception.getMessage(), gson.toJson(exception.getJwtResponse())));
    }
}
