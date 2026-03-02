package com.mediaalterations.authservice.service;

import com.mediaalterations.authservice.config.JwtUtil;
import com.mediaalterations.authservice.dto.LoginRequest;
import com.mediaalterations.authservice.dto.LoginResponse;
import com.mediaalterations.authservice.dto.RedisSessionDetails;
import com.mediaalterations.authservice.dto.SignupRequest;
import com.mediaalterations.authservice.dto.UserDto;
import com.mediaalterations.authservice.entity.Auth;
import com.mediaalterations.authservice.exception.AuthenticationFailedException;
import com.mediaalterations.authservice.exception.SessionExpiredException;
import com.mediaalterations.authservice.exception.UserAlreadyExistsException;
import com.mediaalterations.authservice.exception.UserAlreadyLoggedInException;
import com.mediaalterations.authservice.exception.UserCreationException;
import com.mediaalterations.authservice.exception.UserNotFoundException;
import com.mediaalterations.authservice.feignClients.UserClient;
import com.mediaalterations.authservice.repository.AuthRepository;
import feign.FeignException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.time.Duration;
import java.util.UUID;

import org.springframework.boot.security.autoconfigure.SecurityProperties.User;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

        private final AuthRepository authRepository;
        private final AuthenticationManager authenticationManager;
        private final JwtUtil jwtUtil;
        private final PasswordEncoder passwordEncoder;
        private final UserClient userClient;
        private final RedisService redisService;

        // ========================= LOGIN =========================

        public LoginResponse login(LoginRequest loginRequest, HttpServletResponse httpResponse) {

                log.info("Login attempt for username={}", loginRequest.username());

                try {

                        Authentication authentication = authenticationManager.authenticate(
                                        new UsernamePasswordAuthenticationToken(
                                                        loginRequest.username(),
                                                        loginRequest.password()));

                        Auth user = (Auth) authentication.getPrincipal();

                        String token = jwtUtil.generateToken(user);

                        log.info("Login successful. userId={}", user.getUserId());

                        ResponseEntity<UserDto> response = userClient.getUserById(user.getUserId().toString());

                        if (!response.getStatusCode().is2xxSuccessful()) {
                                log.error("User-service failed to fetch user details. status={}",
                                                response.getStatusCode());

                                throw new AuthenticationFailedException(
                                                "User service failed to fetch user details");
                        }
                        // check if user is already logged in
                        RedisSessionDetails redisSessionDetails = redisService.get("user:" + user.getUserId(),
                                        RedisSessionDetails.class);
                        if (redisSessionDetails != null) {
                                throw new UserAlreadyLoggedInException(
                                                "User is already active in another session "
                                                                + redisSessionDetails.getIpAddress(),
                                                HttpStatus.UNAUTHORIZED.value());
                        }

                        generateSessionIdSaveInRedisAndSetCookie(user.getUserId().toString(), httpResponse);

                        return new LoginResponse(
                                        token,
                                        user.getUserId().toString(), response.getBody());

                } catch (BadCredentialsException ex) {

                        log.warn("Invalid login attempt for username={}",
                                        loginRequest.username());

                        throw new AuthenticationFailedException("Invalid username or password");

                } catch (FeignException ex) {

                        log.error("User-service communication error during signup.",
                                        ex);

                        throw new UserCreationException(
                                        "User service communication failed", ex);

                } catch (UserAlreadyLoggedInException ex) {

                        log.warn("Login attempt for already active user. username={}",
                                        loginRequest.username());

                        throw ex;

                }

                catch (Exception ex) {

                        log.error("Unexpected authentication error for username={} error:{}",
                                        loginRequest.username(), ex.getMessage(), ex);

                        throw new AuthenticationFailedException("Authentication failed");
                }
        }

        // ========================= SIGNUP =========================

        @Transactional
        public LoginResponse signup(SignupRequest signupRequest, HttpServletResponse httpResponse) {

                log.info("Signup attempt for username={}, email={}",
                                signupRequest.username(),
                                signupRequest.email());

                if (authRepository.findByUsername(signupRequest.username()).isPresent()) {

                        log.warn("Signup failed. Username already exists: {}",
                                        signupRequest.username());

                        throw new UserAlreadyExistsException("Username already exists");
                }

                try {

                        Auth auth = new Auth(
                                        signupRequest.username(),
                                        passwordEncoder.encode(signupRequest.password()));

                        // transaction will still rollabck if user-service call fails, while using
                        // saveAndFlush ensures we get the generated user_id immediately for the
                        // user-service call
                        Auth savedAuth = authRepository.saveAndFlush(auth);

                        log.info("Auth record created successfully. userId={}", savedAuth.getUserId());
                        UserDto dto = new UserDto(
                                        savedAuth.getUserId(),
                                        signupRequest.email(),
                                        signupRequest.fullName(),
                                        savedAuth.getCreatedAt());
                        ResponseEntity<UserDto> response = userClient.add(dto);

                        if (!response.getStatusCode().is2xxSuccessful()) {

                                log.error("User-service failed during signup. status={}",
                                                response.getStatusCode());

                                throw new UserCreationException(
                                                "User service failed during signup", null);
                        }

                        log.info("User-service record created successfully. userId={}",
                                        savedAuth.getUserId());

                        String token = jwtUtil.generateToken(savedAuth);

                        log.info("Signup successful. userId={}", savedAuth.getUserId());

                        generateSessionIdSaveInRedisAndSetCookie(savedAuth.getUserId().toString(), httpResponse);

                        return new LoginResponse(
                                        token,
                                        savedAuth.getUserId().toString(),
                                        response.getBody());

                } catch (FeignException ex) {

                        log.error("User-service communication error during signup.",
                                        ex);

                        throw new UserCreationException(
                                        "User service communication failed", ex);

                } catch (Exception ex) {

                        log.error("Unexpected error during signup. username={}",
                                        signupRequest.username(), ex);

                        throw new UserCreationException(
                                        "Signup failed due to internal error", ex);
                }
        }

        private void generateSessionIdSaveInRedisAndSetCookie(String userId, HttpServletResponse httpResponse) {
                // generate refresh token/ sessionId
                String sessionId = UUID.randomUUID().toString();
                log.info("Generated sessionId={} for userId={}", sessionId, userId);
                // save in redis
                redisService.set("user:" + userId, new RedisSessionDetails(sessionId, null), 2L);
                // reverse index required for refreshToken
                redisService.set("session:" + sessionId, userId, 2L);
                // send sessionId in Http Safe cookie
                ResponseCookie refreshCookie = ResponseCookie.from("session", sessionId)
                                .httpOnly(false)// true in prod
                                .secure(true)
                                .path("/auth/refresh")
                                .maxAge(Duration.ofHours(2))
                                .sameSite("Strict")
                                .build();

                httpResponse.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        }

        public ResponseEntity<String> logout(String userId, HttpServletResponse response) {

                // clear user session
                String deletedUserSessionId = redisService.delete("user:" + userId);

                if (deletedUserSessionId == null)
                        log.info("User session didn't exist");

                String deletedUserId = redisService.delete("session:" + deletedUserSessionId);

                ResponseCookie deleteCookie = ResponseCookie.from("session", "")
                                .httpOnly(true)
                                .secure(true)
                                .path("/auth/refresh")
                                .maxAge(0)
                                .build();

                response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

                return ResponseEntity.ok("User logged out successfully");
        }

        public ResponseEntity<String> refresh(String sessionId, HttpServletResponse response) {

                // check if stored sessionId matches the cookie sessionId
                String userId = redisService.get("session:" + sessionId,
                                String.class);
                // rotate the sessionId
                generateSessionIdSaveInRedisAndSetCookie(userId, response);

                // send refreshed jwt in reponse

                var user = authRepository.findById(UUID.fromString(userId))
                                .orElseThrow(() -> new UserNotFoundException("User Not Found"));

                String token = jwtUtil.generateToken(user);
                return ResponseEntity.ok(token);

        }

}
