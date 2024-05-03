package com.example.auth.service;

import com.example.auth.domain.Role;
import com.example.auth.domain.UserAuth;
import com.example.auth.repository.UserRepository;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<UserAuth> getByUsername(@NonNull String username){
        return userRepository.findByUsername(username);
    }

    public boolean create(@NonNull String username, @NonNull String password) {
        if (getByUsername(username).isEmpty()) {
            UserAuth user = new UserAuth();
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(password));
            user.setRoles(Collections.singleton(Role.ROLE_USER));
            userRepository.save(user);
            return true;
        } else {
            return false;
        }
    }
}
