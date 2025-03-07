package com.example.QLNK.controllers.users;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping("/home")
    public String homePage() {
        return "Welcome to the Home Page!";
    }
}
