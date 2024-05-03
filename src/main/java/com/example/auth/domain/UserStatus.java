package com.example.auth.domain;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum UserStatus {
    USER_BANNED("USER_BANNED"),
    USER_ACTIVATED("USER_ACTIVATED"),
    USER_RESTRICTED("USER_RESTRICTED"),
    USER_NOT_ACTIVATED("USER_NOT_ACTIVATED");
    private final String value;
}
