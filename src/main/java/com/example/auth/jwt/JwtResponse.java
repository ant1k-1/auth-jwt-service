package com.example.auth.jwt;

import com.example.auth.domain.AuthStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private final String type = "Bearer";
    private String accessToken;
    private String refreshToken;
    private AuthStatus status;

    public static JwtResponse makeInvalid(AuthStatus status) {
        return new JwtResponse(null, null, status);
    }
    public static JwtResponse makeValid(String accessToken, String refreshToken, AuthStatus status) {
        return new JwtResponse(accessToken, refreshToken, status);
    }

    public String censor(boolean httpOnly) {
        var token = refreshToken;
        if (httpOnly) {
            refreshToken = "hidden";
        }
        return token;
    }

    @Override
    public String toString() {
        return "JwtResponse{" +
                "type='" + type + '\'' +
                ", accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", status=" + status +
                '}';
    }
}
