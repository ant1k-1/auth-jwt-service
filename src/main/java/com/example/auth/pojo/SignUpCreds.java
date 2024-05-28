package com.example.auth.pojo;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignUpCreds {

    @NotBlank(message = "Username cannot be blank")
    @Size(min = 5, max = 30, message = "Username must contain from 5 to 30 characters")
    private String username;

    @NotBlank(message = "Password cannot be blank")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*_)(?!.*[^a-zA-Z0-9_]).{5,30}$", message = "Password must contain 5-30 symbols: [a-z], [A-Z], [0-9], _")
    private String password;

    @Email(message = "Incorrect email format")
    private String email;
}