package com.example.auth.jwt;

import com.example.auth.exception.AuthException;
import com.example.auth.exception.ErrorMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

@Component
public class CustomAuthenticationHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ErrorMessage errorMessage = new ErrorMessage(
                ((AuthException) authException).getHttpStatus().value(),
                ((AuthException) authException).getHttpStatus().name(),
                request.getRequestURI(),
                authException.getMessage()
        );
        response.setStatus(((AuthException) authException).getHttpStatus().value());
        OutputStream responseStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(responseStream, errorMessage);
        responseStream.flush();
        responseStream.close();
    }
}
