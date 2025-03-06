package com.example.QLNK.DTOS.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class LoginUserDTO {
    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;
}
