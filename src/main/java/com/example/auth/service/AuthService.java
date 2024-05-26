package com.example.auth.service;

import com.example.auth.domain.*;
import com.example.auth.exception.AuthException;
import com.example.auth.jwt.JwtProvider;
import com.example.auth.jwt.JwtRequest;
import com.example.auth.jwt.JwtResponse;
import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Set;

@Service
public class AuthService {
    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;
    private final Gson gson;
    private final Integer sessionDurationInDays;
    private final SessionService sessionService;

    @Autowired
    public AuthService(
            UserService userService,
            JwtProvider jwtProvider,
            PasswordEncoder passwordEncoder,
            Gson gson,
            @Value("${session.duration.days}") Integer sessionDurationInDays,
            SessionService sessionService
    ) {
        this.userService = userService;
        this.jwtProvider = jwtProvider;
        this.passwordEncoder = passwordEncoder;
        this.gson = gson;
        this.sessionDurationInDays = sessionDurationInDays;
        this.sessionService = sessionService;
    }

    public JwtResponse login(@NonNull JwtRequest authRequest) {
        final UserAuth userAuth = userService.getByUsername(authRequest.getUsername())
                .orElseThrow(() -> new AuthException(
                        AuthStatus.CREDENTIAL_INVALID,
                        HttpStatus.UNAUTHORIZED,
                        "Incorrect username or password"
                ));
        if (passwordEncoder.matches(authRequest.getPassword(), userAuth.getPassword())) {
            if (sessionService.getAllSessions(userAuth.getUsername()).size() >= 3) {
                sessionService.expireAllSessions(userAuth.getUsername());
            }
            if (userAuth.getStatus().equals(UserStatus.USER_BANNED)) {
                throw new AuthException(
                        AuthStatus.USER_BANNED,
                        HttpStatus.FORBIDDEN,
                        "User has been banned for 'Use of terms' violation"
                );
            }
            final String accessToken = jwtProvider.generateAccessToken(userAuth);
            final String refreshToken = jwtProvider.generateRefreshToken(userAuth);
            Session session = new Session(sessionDurationInDays);
            session.setRefreshToken(refreshToken);
            sessionService.createSession(userAuth.getUsername(), session);
            return new JwtResponse(accessToken, refreshToken, AuthStatus.SESSION_CREATED);
        } else {
            throw new AuthException(
                    AuthStatus.CREDENTIAL_INVALID,
                    HttpStatus.UNAUTHORIZED,
                    "Incorrect username or password"
            );
        }
    }

    public JwtResponse logout(String refreshToken, boolean isLogoutAll) {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String username = claims.getSubject();
            Set<Session> sessions;
            Session session;
            try {
                sessions = sessionService.getAllSessions(username);
                session = sessionService.getSessionByToken(sessions, refreshToken);
            } catch (NullPointerException | NoSuchElementException e) {
                throw new AuthException(
                        AuthStatus.SESSION_DELETED,
                        HttpStatus.BAD_REQUEST,
                        "Session already deleted"
                );
            }
            if (session.isExpired()) {
                sessionService.expireSession(username, session);
                throw new AuthException(
                        AuthStatus.SESSION_DELETED,
                        HttpStatus.UNAUTHORIZED,
                        "Session expired"
                );
            }
            if (sessions.size() >= 3) {
                sessionService.expireAllSessions(username);
                throw new AuthException(
                        AuthStatus.SESSION_DELETED,
                        HttpStatus.UNAUTHORIZED,
                        "Suspicious access. Sessions are cleared"
                );
            }
            UserAuth userAuth = userService.getByUsername(username)
                    .orElseThrow(() -> new AuthException(
                            AuthStatus.CREDENTIAL_INVALID,
                            HttpStatus.UNAUTHORIZED,
                            "Incorrect username or password"
                    ));
            if (isLogoutAll) {
                sessionService.expireAllSessions(username);
            } else {
                sessionService.expireSession(username, session);
            }
            return JwtResponse.makeInvalid(AuthStatus.SESSION_DELETED);
        }
        if (jwtProvider.isExpiredRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String username = claims.getSubject();
            sessionService.expireAllSessions(username);
        }


        throw new AuthException(
                AuthStatus.TOKEN_INVALID,
                HttpStatus.UNAUTHORIZED,
                "Token invalid"
        );
    }

    public JwtResponse getAccessToken(@NonNull String refreshToken) {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String username = claims.getSubject();
            Set<Session> sessions;
            Session session;
            UserAuth userAuth;
            try {
                sessions = sessionService.getAllSessions(username);
                session = sessionService.getSessionByToken(sessions, refreshToken);
                userAuth = userService.getByUsername(username).orElseThrow();
            } catch (NullPointerException | NoSuchElementException e) {
                throw new AuthException(
                        AuthStatus.SESSION_INVALID,
                        HttpStatus.UNAUTHORIZED,
                        "Session invalid"
                );
            }
            if (session.isExpired()) {
                sessionService.expireSession(username, session);
                throw new AuthException(
                        AuthStatus.SESSION_EXPIRED,
                        HttpStatus.UNAUTHORIZED,
                        "Session expired"
                );
            }
            if (sessions.size() >= 3) {
                sessionService.expireAllSessions(username);
                throw new AuthException(
                        AuthStatus.SESSION_INVALID,
                        HttpStatus.UNAUTHORIZED,
                        "Suspicious access. Sessions are cleared"
                );
            }
            final String oldRefreshToken = session.getRefreshToken();
            if (!jwtProvider.isExpiredRefreshToken(oldRefreshToken)
                    && oldRefreshToken.equals(refreshToken)) {
                final String accessToken = jwtProvider.generateAccessToken(userAuth);
                final String newRefreshToken = jwtProvider.generateRefreshToken(userAuth);
                sessionService.refreshSessionToken(username, session, newRefreshToken);
                return JwtResponse.makeValid(accessToken, newRefreshToken, AuthStatus.TOKEN_VALID);
            } else {
                sessionService.expireAllSessions(username);
                throw new AuthException(
                        AuthStatus.SESSION_INVALID,
                        HttpStatus.UNAUTHORIZED,
                        "Suspicious access. Sessions are cleared"
                );
            }
        }
        throw new AuthException(
                AuthStatus.TOKEN_INVALID,
                HttpStatus.UNAUTHORIZED,
                "Token invalid"
        );
    }

    public JwtResponse refresh(@NonNull String refreshToken) {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String username = claims.getSubject();
            Set<Session> sessions;
            Session oldSession;
            try {
                sessions = sessionService.getAllSessions(username);
                oldSession = sessionService.getSessionByToken(sessions, refreshToken);
            } catch (NullPointerException | NoSuchElementException e) {
                throw new AuthException(
                        AuthStatus.SESSION_DELETED,
                        HttpStatus.UNAUTHORIZED,
                        "Session not found"
                );
            }
            if (oldSession.isExpired()) {
                sessionService.expireSession(username, oldSession);
                throw new AuthException(
                        AuthStatus.SESSION_EXPIRED,
                        HttpStatus.UNAUTHORIZED,
                        "Session expired"
                );
            }
            if (sessions.size() >= 3) {
                sessionService.expireAllSessions(username);
                throw new AuthException(
                        AuthStatus.SESSION_DELETED,
                        HttpStatus.UNAUTHORIZED,
                        "Suspicious access. Sessions are cleared"
                );
            }
            UserAuth userAuth = userService.getByUsername(username)
                    .orElseThrow(() -> new AuthException(
                            AuthStatus.CREDENTIAL_INVALID,
                            HttpStatus.UNAUTHORIZED,
                            "Incorrect username or password"
                    ));
            final String newRefreshToken = jwtProvider.generateRefreshToken(userAuth);
            sessionService.refreshSessionToken(username, oldSession, newRefreshToken);
            return JwtResponse.makeValid(null, newRefreshToken, AuthStatus.TOKEN_VALID);

        } else {
            throw new AuthException(
                    AuthStatus.TOKEN_INVALID,
                    HttpStatus.UNAUTHORIZED,
                    "Token invalid"
            );
        }
    }

    public String jsonify(JwtResponse jwtResponse) {
        return gson.toJson(jwtResponse);
    }

    public JwtAuthentication getAuthInfo() {
        return (JwtAuthentication) SecurityContextHolder.getContext().getAuthentication();
    }
}
