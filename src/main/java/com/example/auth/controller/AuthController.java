package com.example.auth.controller;

import com.example.auth.jwt.JwtRequest;
import com.example.auth.jwt.JwtResponse;
import com.example.auth.pojo.RefreshToken;
import com.example.auth.service.AuthService;
import com.example.auth.service.UserService;
//import jakarta.servlet.http.Cookie;
//import org.springframework.boot.web.server.Cookie;
import org.springframework.http.ResponseCookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Optional;

@RequestMapping("/api/auth")
@RestController
public class AuthController {
    private final AuthService authService;
    private final boolean cookieSecure;
    private final int cookieMaxAge;
    private final boolean cookieHttpOnly;
    private final String cookieSameSite;
    private final String cookiePath;
    private final String cookieDomain;
    private final UserService userService;

    @Autowired
    public AuthController(
            AuthService authService,
            @Value("${cookie.secure}") boolean cookieSecure,
            @Value("${cookie.max.age}") int cookieMaxAge,
            @Value("${cookie.httponly}") boolean cookieHttpOnly,
            @Value("${cookie.same.site}") String cookieSameSite,
            @Value("${cookie.path}") String cookiePath,
            @Value("${cookie.domain}") String cookieDomain,
            UserService userService
    ) {
        this.authService = authService;
        this.cookieSecure = cookieSecure;
        this.cookieMaxAge = cookieMaxAge;
        this.cookieHttpOnly = cookieHttpOnly;
        this.userService = userService;
        this.cookieSameSite = cookieSameSite;
        this.cookiePath = cookiePath;
        this.cookieDomain = cookieDomain;
    }

    //TODO: добавить чек, что уже залогинен, и добавить чек фингерпринта браузера, юзер агента мб
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody JwtRequest authRequest, HttpServletResponse response) {
        final JwtResponse token = authService.login(authRequest);
        ResponseCookie cookie = refreshCookie(token.censor(cookieHttpOnly));
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(authService.jsonify(token));
    }

    @PostMapping("/token")
    public ResponseEntity<?> getNewAccessToken(HttpServletRequest request, HttpServletResponse response,
                                               @RequestBody(required = false) Optional<RefreshToken> refreshToken
    ) throws IOException {
        try {
            final JwtResponse token;
            if (cookieHttpOnly) {
                token = authService.getRefreshToken(getRefreshFromCookie(request));
            } else {
                var temp = refreshToken.isPresent() ? refreshToken.get().getRefreshToken() : "qwerty";
                token = authService.getRefreshToken(temp);
            }
            ResponseCookie cookie = refreshCookie(token.censor(cookieHttpOnly));
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(token);
        } catch (NoSuchElementException e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

//    @PostMapping("/refresh")
//    public ResponseEntity<JwtResponse> getNewRefreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
//        try {
//            final JwtResponse token = authService.refresh(getRefreshFromCookie(request));
//            ResponseCookie cookie = refreshCookie(token.censor(cookieHttpOnly));
//            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(token);
//        } catch (NoSuchElementException e) {
//            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
//        }
//    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody JwtRequest authRequest) {
        if (userService.create(authRequest.getUsername(), authRequest.getPassword())) {
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            final JwtResponse token = authService.logout(getRefreshFromCookie(request), false);
            ResponseCookie cookie = refreshCookie(null);
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(token);
        } catch (NoSuchElementException e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

    }
    private String getRefreshFromCookie(HttpServletRequest request) throws NoSuchElementException {
        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals("refresh"))
                .findFirst().orElseThrow().getValue();
    }

    private ResponseCookie refreshCookie(String refreshToken) {
        return ResponseCookie.from("refresh", refreshToken)
                .path(cookiePath)
                .secure(cookieSecure)
                .maxAge(cookieMaxAge)
                .httpOnly(cookieHttpOnly)
                .sameSite(cookieSameSite)
                .domain(cookieDomain)
                .build();
    }
}
