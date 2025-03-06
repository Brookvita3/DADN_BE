package com.example.QLNK.controllers.users;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/home")
public class UserController {

    @GetMapping
    public String homePage() {
        return "Welcome to the Home Page!";
    }
}
