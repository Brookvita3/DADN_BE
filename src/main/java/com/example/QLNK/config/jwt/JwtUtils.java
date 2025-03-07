package com.example.QLNK.config.jwt;

import com.example.QLNK.exception.CustomAuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtUtils {

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    private SecretKey key;

    @PostConstruct
    public void getSignInKey() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    public String generateAccessTokenWithRole(String email,String role) {
        return Jwts.builder()
                .subject(email)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(key)
                .compact();
    }

    public Claims extractClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();}
        catch (Exception e) {
            return null;
        }
    }

    public String extractEmail(String token) {
        try {
            return extractClaims(token).getSubject();}
        catch (Exception e) {
            return null;
        }
    }

    public String extractRole(String token) {
        try {
            return extractClaims(token).get("role", String.class);}
        catch (Exception e) {
            return null;
        }
    }


    public boolean validateSignatureToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            throw new CustomAuthException("Fail in validate signature token", HttpStatus.UNAUTHORIZED);
        }
    }

    public boolean validateSubjectToken(String token) {
        try {
            String email = extractClaims(token).getSubject();
            if (email == null || email.isEmpty()) {
                throw new CustomAuthException("Invalid token subject", HttpStatus.UNAUTHORIZED);
            }
            return true;
        } catch (Exception e) {
            throw new CustomAuthException("Fail in validate subject token", HttpStatus.UNAUTHORIZED);
        }
    }

    public String generatePasswordToken(String email) {
        return Jwts.builder()
                .subject(email)
                .claim("id", UUID.randomUUID().toString())
                .expiration(new Date(System.currentTimeMillis() + 5 * 60 * 1000)) // 15 phút
                .signWith(key)
                .compact();
    }
}
