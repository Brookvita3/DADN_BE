package com.example.QLNK.config.jwt;

import com.example.QLNK.exception.CustomAuthException;
import com.example.QLNK.response.ResponseObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        if (authException instanceof CustomAuthException) {
            status = ((CustomAuthException) authException).getHttpStatus();
        }

        // Tạo response object
        ResponseObject responseObject = ResponseObject.builder()
                .message(authException.getMessage())
                .status(status)
                .data(null)
                .build();

        response.setContentType("application/json");
        response.setStatus(status.value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseObject));
    }
}
