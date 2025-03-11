package com.example.QLNK.services.auth;

import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.exception.TokenExpiredException;
import com.example.QLNK.model.user.User;
import com.example.QLNK.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${jwt.refresh.expiration}")
    private Long refreshExpiration;

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final RedisTemplate<String, String> redisStringTemplate;
    private final RedisTemplate<String, Long> redisLongTemplate;

    public String createRefreshToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String refreshToken = UUID.randomUUID().toString(); // Tạo UUID token
        long now = Instant.now().getEpochSecond();
        String logoutKey = "logout:user:" + email;
        String refreshKey = "refresh:user:" + email;

        redisStringTemplate.opsForValue().set(refreshKey, refreshToken, refreshExpiration, TimeUnit.MILLISECONDS);
        redisLongTemplate.opsForValue().set(logoutKey, now, refreshExpiration, TimeUnit.MILLISECONDS);


        return refreshToken;
    }

    public boolean verifyRefreshToken(String email, String token) {
        String key = "refresh:user:" + email;
        String storedToken = redisStringTemplate.opsForValue().get(key);
        return storedToken != null && storedToken.equals(token);
    }

    public void revokeRefreshTokenByEmail(String email) {
        String key = "refresh:user:" + email;
        redisStringTemplate.delete(key);
    }

    public void setLogoutTimeByEmail(String email) {
        String key = "logout:user:" + email;
        redisLongTemplate.opsForValue().set(key, Instant.now().getEpochSecond(), refreshExpiration, TimeUnit.MILLISECONDS);
    }
}
