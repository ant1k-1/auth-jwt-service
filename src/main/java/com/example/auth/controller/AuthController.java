package com.example.auth.controller;

import com.example.auth.jwt.JwtRequest;
import com.example.auth.jwt.JwtResponse;
import com.example.auth.service.AuthService;
import com.example.auth.service.UserService;
import jakarta.servlet.http.Cookie;
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

@RequestMapping("/api/auth")
@RestController
public class AuthController {
    private final AuthService authService;
    private final boolean cookieSecure;
    private final int cookieMaxAge;
    private final boolean cookieHttpOnly;
    private final UserService userService;

    @Autowired
    public AuthController(
            AuthService authService,
            @Value("${cookie.secure}") boolean cookieSecure,
            @Value("${cookie.max.age}") int cookieMaxAge,
            @Value("${cookie.httponly}") boolean cookieHttpOnly,
            UserService userService
    ) {
        this.authService = authService;
        this.cookieSecure = cookieSecure;
        this.cookieMaxAge = cookieMaxAge;
        this.cookieHttpOnly = cookieHttpOnly;
        this.userService = userService;
    }

    //TODO: добавить чек, что уже залогинен, и добавить чек фингерпринта браузера, юзер агента мб
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody JwtRequest authRequest, HttpServletResponse response) {
        final JwtResponse token = authService.login(authRequest);
        Cookie cookie = refreshCookie(token.censor());
        response.addCookie(cookie);
        return new ResponseEntity<>(authService.jsonify(token), HttpStatus.OK);
    }

    @PostMapping("/token")
    public ResponseEntity<?> getNewAccessToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            final JwtResponse token = authService.getAccessToken(getRefreshFromCookie(request));
            Cookie cookie = refreshCookie(token.censor());
            response.addCookie(cookie);
            return ResponseEntity.ok(token);
        } catch (NoSuchElementException e) {
            response.sendRedirect("/api/auth/login");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> getNewRefreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            final JwtResponse token = authService.refresh(getRefreshFromCookie(request));
            Cookie cookie = refreshCookie(token.censor());
            response.addCookie(cookie);
            return ResponseEntity.ok(token);
        } catch (NoSuchElementException e) {
            response.sendRedirect("/api/auth/login");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

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
            Cookie cookie = refreshCookie(null);
            response.addCookie(cookie);
            return ResponseEntity.ok(token);
        } catch (NoSuchElementException e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

    }
    private String getRefreshFromCookie(HttpServletRequest request) throws NoSuchElementException {
        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals("refresh"))
                .findFirst().orElseThrow().getValue();
    }

    private Cookie refreshCookie(String refreshToken) {
        Cookie cookie = new Cookie("refresh", refreshToken);
        cookie.setPath("/api/auth");
        cookie.setSecure(cookieSecure);
        cookie.setMaxAge(cookieMaxAge);
        cookie.setHttpOnly(cookieHttpOnly);
        return cookie;
    }
}
