package com.example.auth.jwt;

import com.example.auth.domain.AuthStatus;
import com.example.auth.domain.JwtAuthentication;
import com.example.auth.domain.UserStatus;
import com.example.auth.exception.AuthException;
import com.example.auth.util.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Arrays;
import java.util.NoSuchElementException;

@Component
public class JwtFilter extends GenericFilterBean {
    private static final String AUTHORIZATION = "Authorization";
    private final JwtProvider jwtProvider;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final boolean cookieHttpOnly;

    @Autowired
    public JwtFilter(JwtProvider jwtProvider,
                     AuthenticationEntryPoint authenticationEntryPoint,
                     @Value("${cookie.httponly}") boolean cookieHttpOnly) {
        this.jwtProvider = jwtProvider;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.cookieHttpOnly = cookieHttpOnly;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain fc)
            throws IOException, ServletException, NoSuchElementException {
        final String accessToken = getAccessTokenFromRequest((HttpServletRequest) request);
        final String refreshToken = getRefreshTokenFromRequest((HttpServletRequest) request);
//        System.out.println(refreshToken);
        if (cookieHttpOnly
                && refreshToken != null
                && jwtProvider.validateRefreshToken(refreshToken)
                && accessToken == null
                && ( ((HttpServletRequest) request).getRequestURI().contains("api/auth/token")
                || ((HttpServletRequest) request).getRequestURI().contains("/api/auth/logout") )
        ) {
//            System.out.println("Go api/auth/token");лютый костылище
        } else if (!cookieHttpOnly
                && ( ((HttpServletRequest) request).getRequestURI().contains("api/auth/token")
                || ((HttpServletRequest) request).getRequestURI().contains("/api/auth/logout") )
        ) {
            //пропускаем костыльный рефреш токен
        } else
        if (accessToken != null && refreshToken != null) {
            if (jwtProvider.isExpiredAccessToken(accessToken) || jwtProvider.isExpiredRefreshToken(refreshToken)) {
                authenticationEntryPoint.commence(
                        (HttpServletRequest) request,
                        (HttpServletResponse) response,
                        new AuthException(
                                AuthStatus.TOKEN_EXPIRED,
                                HttpStatus.UNAUTHORIZED
                        )
                );
                return;
            }
            if (!jwtProvider.validateAccessToken(accessToken) || !jwtProvider.validateRefreshToken(refreshToken)) {
                authenticationEntryPoint.commence(
                        (HttpServletRequest) request,
                        (HttpServletResponse) response,
                        new AuthException(
                                AuthStatus.TOKEN_INVALID,
                                HttpStatus.UNAUTHORIZED
                        )
                );
                return;
            }
            final Claims claims = jwtProvider.getAccessClaims(accessToken);
            final JwtAuthentication jwtInfoToken = JwtUtils.generate(claims);
            if (jwtInfoToken.getStatus().equals(UserStatus.USER_BANNED)
                    || jwtInfoToken.getStatus().equals(UserStatus.USER_NOT_ACTIVATED)
            ) {
                authenticationEntryPoint.commence(
                        (HttpServletRequest) request,
                        (HttpServletResponse) response,
                        new AuthException(
                                AuthStatus.USER_BANNED,
                                HttpStatus.FORBIDDEN,
                                "User has been banned for 'Use of terms' violation"
                        )
                );
                return;
            } else {
                jwtInfoToken.setAuthenticated(true);
                SecurityContextHolder.getContext().setAuthentication(jwtInfoToken);
            }
        }

        fc.doFilter(request, response);
    }
    private String getAccessTokenFromRequest(HttpServletRequest request) {
        final String bearer = request.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
    private String getRefreshTokenFromRequest(HttpServletRequest request) {
        try {
            return Arrays.stream(request.getCookies())
                    .filter(c -> c.getName().equals("refresh"))
                    .findFirst().orElseThrow().getValue();
        } catch (NoSuchElementException | NullPointerException e) {
            return null;
        }
    }
}
