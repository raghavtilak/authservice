package com.mediaalterations.authservice.controller;

import com.mediaalterations.authservice.dto.LoginRequest;
import com.mediaalterations.authservice.dto.LoginResponse;
import com.mediaalterations.authservice.dto.SignupRequest;
import com.mediaalterations.authservice.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(loginRequest, response));
    }

    @PostMapping("/signup")
    public ResponseEntity<LoginResponse> signup(@RequestBody SignupRequest signupRequest,
            HttpServletResponse response) {
        return ResponseEntity.ok(authService.signup(signupRequest, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue("session") String sessionId, HttpServletResponse response) {
        return authService.logout(sessionId, response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refresh(
            @CookieValue("session") String sessionId,
            HttpServletResponse response) {
        // here sessionId==refresh token
        log.info("refreshToken api call sessionId {}", sessionId);
        return authService.refresh(sessionId, response);
    }
}
