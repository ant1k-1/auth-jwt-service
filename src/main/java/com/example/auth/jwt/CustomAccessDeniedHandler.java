package com.example.auth.jwt;

import com.example.auth.exception.ErrorMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException
    {
        if (!response.isCommitted()) {
            ObjectMapper mapper = new ObjectMapper();
            ErrorMessage errorMessage = new ErrorMessage(
                    HttpStatus.FORBIDDEN.value(),
                    HttpStatus.FORBIDDEN.name(),
                    request.getRequestURI(),
                    "ACCESS_DENIED"
            );
            response.setStatus(403);
            OutputStream out = response.getOutputStream();
            mapper.writeValue(out, errorMessage);
            out.flush();
            out.close();
        }
    }
}
