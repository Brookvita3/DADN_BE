package com.example.QLNK.exception.handler;

import com.example.QLNK.exception.CustomAuthException;
import com.example.QLNK.exception.EmailException;
import com.example.QLNK.exception.TokenExpiredException;
import com.example.QLNK.response.ResponseObject;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ResponseObject> handleValidationException(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult()
                .getAllErrors()
                .stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(", "));

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                ResponseObject.builder()
                        .message(errorMessage)
                        .status(HttpStatus.BAD_REQUEST)
                        .data(null)
                        .build()
        );
    }

    @ExceptionHandler(CustomAuthException.class)
    public ResponseEntity<ResponseObject> handleAuthException(CustomAuthException ex) {
        return ResponseEntity.status(ex.getHttpStatus()).body(
                ResponseObject.builder()
                        .message(ex.getMessage())
                        .status(ex.getHttpStatus())
                        .data(null)
                        .build()
        );
    }

    @ExceptionHandler(EmailException.class)
    public ResponseEntity<ResponseObject> handleEmailException(EmailException ex) {
        return ResponseEntity.status(ex.getHttpStatus()).body(
                ResponseObject.builder()
                        .message(ex.getMessage())
                        .status(ex.getHttpStatus())
                        .data(null)
                        .build()
        );
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ResponseObject> handleTokenExpiredException(TokenExpiredException ex) {
        return ResponseEntity.status(ex.getHttpStatus()).body(
                ResponseObject.builder()
                        .message(ex.getMessage())
                        .status(ex.getHttpStatus())
                        .data(null)
                        .build()
        );
    }
}
