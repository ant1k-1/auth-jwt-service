package com.example.auth.repository;

import com.example.auth.domain.UserAuth;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserAuth, Long> {
    Optional<UserAuth> findByUsername(String username);
}
