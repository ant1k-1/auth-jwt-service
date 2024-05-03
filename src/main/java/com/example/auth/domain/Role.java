package com.example.auth.domain;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {
    ROLE_ADMIN("ROLE_ADMIN"),
    ROLE_USER("ROLE_USER"),
    ROLE_MODER("ROLE_MODER");

    private final String value;

    @Override
    public String getAuthority() {
        return value;
    }
}
