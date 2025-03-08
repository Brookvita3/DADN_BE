package com.example.QLNK.services.auth;

import com.example.QLNK.DTOS.token.RefreshTokenRequestDTO;
import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.exception.CustomAuthException;
import com.example.QLNK.exception.TokenExpiredException;
import com.example.QLNK.model.token.RefreshToken;
import com.example.QLNK.model.user.User;
import com.example.QLNK.response.auth.AuthResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public AuthResponse authenticateUser(String email, String password) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            User user = (User) authentication.getPrincipal();

            refreshTokenService.revokeRefreshTokenByEmail(user.getEmail());

            String accessToken = jwtUtils.generateAccessTokenWithRole(user.getEmail(), "USER");
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            return new AuthResponse(accessToken, refreshToken.getToken());
        } catch (BadCredentialsException e) {
            throw new CustomAuthException("Invalid email or password", HttpStatus.UNAUTHORIZED);
        }
    }


    public AuthResponse verifyRefreshToken(RefreshTokenRequestDTO requestDTO) {

        RefreshToken refreshToken = refreshTokenService.findByToken(requestDTO.getRefreshToken())
                .orElseThrow(() -> new TokenExpiredException("Invalid refresh token", HttpStatus.UNAUTHORIZED));

        refreshTokenService.verifyExpiration(refreshToken);

        String newAccessToken = jwtUtils.generateAccessTokenWithRole(refreshToken.getUser().getEmail(), "USER");

        return new AuthResponse(newAccessToken, requestDTO.getRefreshToken());
    }


    public User getAuthenticatedUser(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof User)) {
            throw new CustomAuthException("User not authenticated", HttpStatus.UNAUTHORIZED);
        }
        return (User) authentication.getPrincipal();
    }


    public void logOut(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String authType = authentication.getAuthorities().toString();

        if (authType.contains("OAUTH2_USER")) {
            System.out.println("✅ OAuth2 logging out");
            new SecurityContextLogoutHandler().logout(request, response, authentication);
            return;
        }

        System.out.println("✅ Username/Password logging out");
        User user = getAuthenticatedUser(authentication);

        refreshTokenService.revokeRefreshTokenByEmail(user.getEmail());

        new SecurityContextLogoutHandler().logout(request, response, authentication);
    }
}
