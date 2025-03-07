package com.example.QLNK.services.users;

import com.example.QLNK.DTOS.user.RegisterUserDTO;
import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.exception.CustomAuthException;
import com.example.QLNK.exception.EmailException;
import com.example.QLNK.mapper.UserMapper;
import com.example.QLNK.model.User;
import com.example.QLNK.repositories.UserRepository;
import com.example.QLNK.services.email.EmailService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final JwtUtils jwtUtils;
    private final UserMapper userMapper;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    private final static String link = "http://localhost:8080";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with: " + username));
    }

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

    public void resetPassword(String email, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(()->new CustomAuthException("Email are not sign up", HttpStatus.UNAUTHORIZED));
        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        userRepository.save(user);
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



}
