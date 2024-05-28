package com.example.auth.service;

import com.example.auth.domain.Role;
import com.example.auth.domain.UserAuth;
import com.example.auth.domain.UserStatus;
import com.example.auth.pojo.SignUpCreds;
import com.example.auth.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import java.util.Collections;
import java.util.Optional;

@Validated
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final boolean emailVerificationIsRequired;

    @Autowired
    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${user.email.verification.enabled}") boolean emailVerificationIsRequired
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailVerificationIsRequired = emailVerificationIsRequired;
    }

    public Optional<UserAuth> getByUsername(@NonNull String username){
        return userRepository.findByUsername(username);
    }

    public boolean create(@Valid SignUpCreds signUpCreds) {
        if (getByUsername(signUpCreds.getUsername()).isEmpty()) {
            UserAuth user = new UserAuth();
            user.setUsername(signUpCreds.getUsername());
            user.setPassword(passwordEncoder.encode(signUpCreds.getPassword()));
            user.setEmail(signUpCreds.getEmail());
            user.setStatus(emailVerificationIsRequired ? UserStatus.USER_NOT_ACTIVATED : UserStatus.USER_ACTIVATED);
            user.setRoles(Collections.singleton(Role.ROLE_USER));
            userRepository.save(user);
            return true;
        } else {
            return false;
        }
    }
}
