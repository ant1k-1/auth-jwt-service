package com.example.auth.jwt;

import com.example.auth.domain.AuthStatus;
import com.example.auth.domain.UserAuth;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.security.Key;

@Slf4j
@Component
public class JwtProvider {
    private final SecretKey jwtAccessSecret;
    private final SecretKey jwtRefreshSecret;
    private final Integer jwtAccessTokenDuration;
    private final Integer jwtRefreshTokenDuration;

    public JwtProvider(
            @Value("${jwt.secret.access}") String jwtAccessSecret,
            @Value("${jwt.secret.refresh}") String jwtRefreshSecret,
            @Value("${jwt.duration.mins.access}") Integer jwtAccessTokenDuration,
            @Value("${jwt.duration.days.refresh}") Integer jwtRefreshTokenDuration
    ) {
        this.jwtAccessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtAccessSecret.strip()));
        this.jwtRefreshSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtRefreshSecret.strip()));
        this.jwtAccessTokenDuration = jwtAccessTokenDuration;
        this.jwtRefreshTokenDuration = jwtRefreshTokenDuration;
    }

    public String generateAccessToken(@NonNull UserAuth userAuth) {
        final LocalDateTime now = LocalDateTime.now();
        final Instant accessExpirationInstant = now
                .plusMinutes(jwtAccessTokenDuration)
                .atZone(ZoneId.systemDefault())
                .toInstant();
        final Date accessExpiration = Date.from(accessExpirationInstant);
        return Jwts.builder()
                .setSubject(userAuth.getUsername())
                .setExpiration(accessExpiration)
                .signWith(jwtAccessSecret)
                .claim("roles", userAuth.getRoles())
                .claim("user_id", userAuth.getUserId())
                .claim("status", userAuth.getStatus().name())
                .compact();
    }

    public String generateRefreshToken(@NonNull UserAuth userAuth) {
        final LocalDateTime now = LocalDateTime.now();
        final Instant refreshExpirationInstant = now
                .plusDays(jwtRefreshTokenDuration)
                .atZone(ZoneId.systemDefault())
                .toInstant();
        final Date refreshExpiration = Date.from(refreshExpirationInstant);
        return Jwts.builder()
                .setSubject(userAuth.getUsername())
                .setExpiration(refreshExpiration)
                .signWith(jwtRefreshSecret)
                .compact();
    }

    public boolean validateAccessToken(@NonNull String accessToken) {
        return validateToken(accessToken, jwtAccessSecret).equals(AuthStatus.TOKEN_VALID);
    }

    public boolean validateRefreshToken(@NonNull String refreshToken) {
        return validateToken(refreshToken, jwtRefreshSecret).equals(AuthStatus.TOKEN_VALID);
    }

    public boolean isExpiredAccessToken(@NonNull String token) {
        return validateToken(token, jwtAccessSecret).equals(AuthStatus.TOKEN_EXPIRED);
    }

    public boolean isExpiredRefreshToken(@NonNull String token) {
        return validateToken(token, jwtRefreshSecret).equals(AuthStatus.TOKEN_EXPIRED);
    }

    private AuthStatus validateToken(@NonNull String token, @NonNull Key secret) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .build()
                    .parseClaimsJws(token);
            return AuthStatus.TOKEN_VALID;
        } catch (ExpiredJwtException expEx) {
//            log.error("Token expired", expEx);
            return AuthStatus.TOKEN_EXPIRED;
        } catch (UnsupportedJwtException unsEx) {
//            log.error("Unsupported jwt", unsEx);
            return AuthStatus.TOKEN_UNSUPPORTED;
        } catch (MalformedJwtException mjEx) {
//            log.error("Malformed jwt", mjEx);
            return AuthStatus.TOKEN_MALFORMED;
        } catch (SignatureException sEx) {
//            log.error("Invalid signature", sEx);
            return AuthStatus.TOKEN_INVALID_SIGNATURE;
        } catch (Exception e) {
//            log.error("invalid token", e);
            return AuthStatus.TOKEN_INVALID;
        }
    }

    public Claims getAccessClaims(@NonNull String token) {
        return getClaims(token, jwtAccessSecret);
    }

    public Claims getRefreshClaims(@NonNull String token) {
        return getClaims(token, jwtRefreshSecret);
    }

    private Claims getClaims(@NonNull String token, @NonNull Key secret) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
