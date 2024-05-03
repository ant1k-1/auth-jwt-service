package com.example.auth.exception;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class ErrorMessage {
    private String timestamp;
    private Integer status;
    private String error;
    private String message;
    private String path;

    public ErrorMessage(Integer status, String error, String path, String message) {
        this.status = status;
        this.error = error;
        this.path = path;
        this.message = message;
        this.timestamp = LocalDateTime.now().toString();
    }

    public ErrorMessage(String message) {
        this.message = message;
        this.timestamp = LocalDateTime.now().toString();
    }

    public ErrorMessage(Integer status, String error, String message) {
        this.status = status;
        this.error = error;
        this.message = message;
        this.timestamp = LocalDateTime.now().toString();
    }
}
