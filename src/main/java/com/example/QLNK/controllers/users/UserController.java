package com.example.QLNK.controllers.users;

import com.example.QLNK.config.jwt.JwtUtils;
import com.example.QLNK.response.ResponseObject;
import com.example.QLNK.services.adafruit.AdafruitService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {

    private final JwtUtils jwtUtils;
    private final AdafruitService adafruitService;

    @GetMapping("/home")
    public String homePage() {
        return "Welcome to the Home Page!";
    }

    @GetMapping("/groups")
    public ResponseEntity<?> getAllGroups(@RequestHeader("Authorization") String authHeader, Authentication authentication) {
        String accessToken = authHeader.replace("Bearer ", "");
        String email = jwtUtils.extractEmail(accessToken);
        System.out.println("Current Authentication: " + authentication);
        return ResponseEntity.status(HttpStatus.OK).body(ResponseObject.builder()
                .status(HttpStatus.OK)
                .message("List group")
                .data(adafruitService.getGroups(email))
                .build());
    }
}
