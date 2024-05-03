package com.example.auth.service;

import com.example.auth.domain.Session;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class SessionService {
    private final RedisTemplate<String, String> redisTemplate;
    private final Gson gson;

    @Autowired
    public SessionService(RedisTemplate<String, String> redisTemplate, Gson gson) {
        this.redisTemplate = redisTemplate;
        this.gson = gson;
    }

    public void createSession(String username, Session session) {
        redisTemplate.opsForSet().add(username, gson.toJson(session));
    }

    public Set<Session> getAllSessions(String username) throws NullPointerException{
        return Objects.requireNonNull(redisTemplate.opsForSet().members(username))
                .stream().map(s -> gson.fromJson(s, Session.class))
                .collect(Collectors.toSet());
    }

    public Session getSessionByToken(Set<Session> sessions, String token)
            throws NoSuchElementException
    {
        return sessions.stream()
                .filter(session -> session.getRefreshToken().equals(token))
                .findFirst().orElseThrow();
    }

    public void expireSession(String username, Session session) {
        redisTemplate.opsForSet().remove(username, gson.toJson(session));
    }

    public void expireAllSessions(String username) {
        Set<Session> sessions = getAllSessions(username);
        for (var session : sessions) {
            expireSession(username, session);
        }
    }


    public void refreshSessionToken(String username, Session session, String newRefreshToken) {
        expireSession(username, session);
        session.setRefreshToken(newRefreshToken);
        createSession(username, session);
    }
}
