package com.example.QLNK.services.auth;

import com.example.QLNK.exception.TokenExpiredException;
import com.example.QLNK.model.token.RefreshToken;
import com.example.QLNK.model.user.User;
import com.example.QLNK.repositories.RefreshTokenRepository;
import com.example.QLNK.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${jwt.refresh.expiration}")
    private Long refreshExpiration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshToken createRefreshToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiresAt(Instant.now().plusMillis(refreshExpiration));

        return refreshTokenRepository.save(refreshToken);
    }

    public void verifyExpiration(RefreshToken token) throws TokenExpiredException {
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new TokenExpiredException("Refresh token expired. Please login again.", HttpStatus.UNAUTHORIZED);
        }
    }


    public void revokeRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public void revokeRefreshTokenByUsername(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @Transactional
    public void revokeRefreshTokenByEmail(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        user.ifPresent(refreshTokenRepository::deleteByUser);
    }


//    public void revokeAllTokensByUser(User user) {
//        refreshTokenRepository.deleteByUser(user);
//    }
}
