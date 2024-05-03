package com.example.auth.controller;

import com.example.auth.domain.Session;
import com.example.auth.service.UserService;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RequestMapping("/test")
@RestController
public class TestController {
    private final UserService userService;
    private final RedisTemplate<String, String> redisTemplate;
    private final Gson gson;

    @Autowired
    public TestController(UserService userService, RedisTemplate<String, String> redisTemplate, Gson gson) {
        this.userService = userService;
        this.redisTemplate = redisTemplate;
        this.gson = gson;
    }


    @PostMapping("/putRedis/{username}")
    public ResponseEntity<String> testRedisput(
            @RequestBody Session session,
            @PathVariable("username") String username
    ) {
        String json = gson.toJson(session);
        redisTemplate.opsForSet().add(username, json);
        Set<String> found = redisTemplate.opsForSet().members(username);
        return new ResponseEntity<>(found.toString(), HttpStatus.OK);
    }

    @GetMapping("/getUser/{username}")
    public ResponseEntity<String> testPostgresql(
            @PathVariable("username") String username
    ) {
        return new ResponseEntity<>(userService.getByUsername(username).get().toString(), HttpStatus.OK);
    }

}
