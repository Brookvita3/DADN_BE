package com.example.QLNK.controllers.auth;

import com.example.QLNK.DTOS.token.RefreshTokenRequestDTO;
import com.example.QLNK.DTOS.user.LoginUserDTO;
import com.example.QLNK.DTOS.user.RegisterUserDTO;
import com.example.QLNK.exception.CustomAuthException;
import com.example.QLNK.exception.TokenExpiredException;
import com.example.QLNK.model.User;
import com.example.QLNK.response.auth.AuthResponse;
import com.example.QLNK.response.ResponseObject;
import com.example.QLNK.services.auth.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;


// Nho tach service ra khoi controller
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginUserDTO loginRequest) {
        try {
            AuthResponse authResponse = authService.authenticateUser(loginRequest.getEmail(), loginRequest.getPassword());
            return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
                    .message("Login successful")
                    .status(HttpStatus.OK)
                    .data(authResponse)
                    .build());
        } catch (CustomAuthException e) {
            return ResponseEntity.status(e.getHttpStatus()).body(
                    ResponseObject.builder()
                            .message(e.getMessage())
                            .status(e.getHttpStatus())
                            .data(null)
                            .build()
            );
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshAccessToken(@RequestBody RefreshTokenRequestDTO requestDTO) throws TokenExpiredException {
        try {
            AuthResponse authResponse = authService.verifyRefreshToken(requestDTO);
            return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
                    .message("New refresh token + access token")
                    .status(HttpStatus.OK)
                    .data(authResponse)
                    .build());

        } catch (CustomAuthException e) {
            return ResponseEntity.status(e.getHttpStatus()).body(
                    ResponseObject.builder()
                            .message(e.getMessage())
                            .status(e.getHttpStatus())
                            .data(null)
                            .build()
            );
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterUserDTO registerUserDTO) {
        try {
            authService.registerUser(registerUserDTO);
            return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
                    .message("Register successful")
                    .status(HttpStatus.OK)
                    .data(registerUserDTO)
                    .build());
        }
        catch (CustomAuthException e) {
            return ResponseEntity.status(e.getHttpStatus()).body(
                    ResponseObject.builder()
                            .message(e.getMessage())
                            .status(e.getHttpStatus())
                            .data(null)
                            .build()
            );
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try{
            User user = authService.getAuthenticatedUser(authentication);
            authService.logOut(request, response, authentication);

            // Xóa cookie refresh_token
            Cookie refreshTokenCookie = new Cookie("refresh_token", null);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(0); // Xoá cookie ngay lập tức
            response.addCookie(refreshTokenCookie);

            return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
                    .status(HttpStatus.OK)
                    .message("Logout successful")
                    .data(null)
                    .build());
        }
        catch (CustomAuthException e) {
            return ResponseEntity.status(e.getHttpStatus()).body(
                    ResponseObject.builder()
                            .message(e.getMessage())
                            .status(e.getHttpStatus())
                            .data(null)
                            .build()
            );
        }
    }

    @GetMapping("/google/login")
    public void loginWithGoogle(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }



//    // Nguoi dung se hoan thanh profile tai day
//    @GetMapping("/complete-profile")
//    public ResponseEntity<?> completeProfile(HttpServletRequest request) {
//
//        String jwt = getJwtFromCookies(request);
//        if (jwt == null) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is missing");
//        }
//
//        String role = jwtUtils.extractRole(jwt);
//        if (role == null) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
//        }
//
//        if (!"INCOMPLETE_USER".equals(role)) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
//        }
//        return ResponseEntity.ok("Need Complete your profile");
//    }



//    @PostMapping("/logout")
//    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//
//        if (authentication == null) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not logged in");
//        }
//        String authType = authentication.getAuthorities().toString();
//        Object principal = authentication.getPrincipal();
//        String email = ((User) principal).getEmail();
//
//        System.out.println("✅ Logging out user: " + email);
//
//        if (authType.contains("OAUTH2_USER")) {
//            System.out.println("✅ oauth2 logging out " + email);
//            new SecurityContextLogoutHandler().logout(request, response, authentication);
//            return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
//                    .status(HttpStatus.OK)
//                    .message("OAuth2 logout successful")
//                    .data(null)
//                    .build());
//
//        } else {
//            refreshTokenService.revokeRefreshTokenByEmail(email);
//
//            System.out.println("✅ username password logging out " + email);
//
//            Cookie refreshTokenCookie = new Cookie("refresh_token", null);
//            refreshTokenCookie.setHttpOnly(true);
//            refreshTokenCookie.setSecure(true);
//            refreshTokenCookie.setPath("/");
//            refreshTokenCookie.setMaxAge(0); // Xoá cookie
//            response.addCookie(refreshTokenCookie);
//
//            new SecurityContextLogoutHandler().logout(request, response, authentication);
//            return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
//                    .status(HttpStatus.OK)
//                    .message("Username/Password logout successful")
//                    .data(null)
//                    .build());
//        }
//    }
//


//    private String getJwtFromCookies(HttpServletRequest request) {
//        if (request.getCookies() != null) {
//            Optional<Cookie> jwtCookie = Arrays.stream(request.getCookies())
//                    .filter(cookie -> "JWT-TOKEN".equals(cookie.getName()))
//                    .findFirst();
//            return jwtCookie.map(Cookie::getValue).orElse(null);
//        }
//        return null;
//    }

}
