package com.example.auth.domain;

import lombok.*;
import org.springframework.beans.factory.annotation.Value;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
public class Session implements Serializable {
    private String sessionId;
    private String refreshToken;
//    private String fingerprint;
//    private String ip;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;

    public Session(Integer sessionDuration) {
        sessionId = String.valueOf(UUID.randomUUID());
        createdAt = LocalDateTime.now();
        expiresAt = LocalDateTime.now().plusDays(sessionDuration);
    }

    public boolean isExpired() {
        return expiresAt.isBefore(LocalDateTime.now());
    }
}
