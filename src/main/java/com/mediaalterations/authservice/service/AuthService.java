package com.mediaalterations.authservice.service;

import com.mediaalterations.authservice.config.JwtUtil;
import com.mediaalterations.authservice.dto.LoginRequest;
import com.mediaalterations.authservice.dto.LoginResponse;
import com.mediaalterations.authservice.dto.SignupRequest;
import com.mediaalterations.authservice.dto.UserDto;
import com.mediaalterations.authservice.entity.Auth;
import com.mediaalterations.authservice.exception.AuthenticationFailedException;
import com.mediaalterations.authservice.exception.UserAlreadyExistsException;
import com.mediaalterations.authservice.exception.UserCreationException;
import com.mediaalterations.authservice.feignClients.UserClient;
import com.mediaalterations.authservice.repository.AuthRepository;
import feign.FeignException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.boot.security.autoconfigure.SecurityProperties.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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

        // ========================= LOGIN =========================

        public LoginResponse login(LoginRequest loginRequest) {

                log.info("Login attempt for username={}", loginRequest.username());

                try {

                        Authentication authentication = authenticationManager.authenticate(
                                        new UsernamePasswordAuthenticationToken(
                                                        loginRequest.username(),
                                                        loginRequest.password()));

                        Auth user = (Auth) authentication.getPrincipal();

                        String token = jwtUtil.generateToken(user);

                        log.info("Login successful. userId={}", user.getUser_id());

                        ResponseEntity<UserDto> response = userClient.getUserById(user.getUser_id().toString());

                        if (!response.getStatusCode().is2xxSuccessful()) {
                                log.error("User-service failed to fetch user details. status={}",
                                                response.getStatusCode());

                                throw new AuthenticationFailedException(
                                                "User service failed to fetch user details");
                        }

                        return new LoginResponse(
                                        token,
                                        user.getUser_id().toString(), response.getBody());

                } catch (BadCredentialsException ex) {

                        log.warn("Invalid login attempt for username={}",
                                        loginRequest.username());

                        throw new AuthenticationFailedException("Invalid username or password");

                } catch (FeignException ex) {

                        log.error("User-service communication error during signup.",
                                        ex);

                        throw new UserCreationException(
                                        "User service communication failed", ex);

                } catch (Exception ex) {

                        log.error("Unexpected authentication error for username={}",
                                        loginRequest.username(), ex);

                        throw new AuthenticationFailedException("Authentication failed");
                }
        }

        // ========================= SIGNUP =========================

        @Transactional
        public LoginResponse signup(SignupRequest signupRequest) {

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

                        ResponseEntity<UserDto> response = userClient.add(
                                        new UserDto(
                                                        savedAuth.getUser_id(),
                                                        signupRequest.email(),
                                                        signupRequest.fullName(),
                                                        null));

                        if (!response.getStatusCode().is2xxSuccessful()) {

                                log.error("User-service failed during signup. status={}",
                                                response.getStatusCode());

                                throw new UserCreationException(
                                                "User service failed during signup", null);
                        }

                        log.info("User-service record created successfully. userId={}",
                                        savedAuth.getUser_id());

                        String token = jwtUtil.generateToken(savedAuth);

                        log.info("Signup successful. userId={}", savedAuth.getUser_id());

                        return new LoginResponse(
                                        token,
                                        savedAuth.getUser_id().toString(),
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

}
