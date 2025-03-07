package com.example.QLNK.services.auth;

import com.example.QLNK.DTOS.token.RefreshTokenRequestDTO;
import com.example.QLNK.DTOS.user.RegisterUserDTO;
import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.exception.CustomAuthException;
import com.example.QLNK.exception.EmailException;
import com.example.QLNK.exception.TokenExpiredException;
import com.example.QLNK.mapper.UserMapper;
import com.example.QLNK.model.RefreshToken;
import com.example.QLNK.model.User;
import com.example.QLNK.repositories.UserRepository;
import com.example.QLNK.response.auth.AuthResponse;
import com.example.QLNK.services.email.EmailService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    private final static String link = "http://localhost:8080";

    public void registerUser(RegisterUserDTO registerDTO) {
        if (userRepository.findByEmail(registerDTO.getEmail()).isPresent()) {
            throw new CustomAuthException("Email already register", HttpStatus.UNAUTHORIZED);
        }

        User user = userMapper.registerUserDTOToUser(registerDTO, passwordEncoder);
        userRepository.save(user);
        try {
            String text = "Bạn đã đăng ký thành công trên trang web QLNK";
            emailService.sendMailToUser(registerDTO.getEmail(), "Đăng ký thành công", text);
        }
        catch (Exception e) {
            throw new EmailException("Failed to send email to " + registerDTO.getEmail(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

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

    public void forgotPassword(String email) {
        String token = jwtUtils.generatePasswordToken(email);
        String resetLink = link + "/auth/reset-password?token=" + token;

        try {
            emailService.sendMailToUser(email, "Reset your password", "Click the link to reset your password: " + resetLink);
        } catch (Exception e) {
            throw new EmailException("Error when send magic link mail", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void resetPassword(String email, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(()->new CustomAuthException("Email are not sign up", HttpStatus.UNAUTHORIZED));
        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        userRepository.save(user);
    }
}
