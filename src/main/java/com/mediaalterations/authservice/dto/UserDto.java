package com.mediaalterations.authservice.dto;

import java.time.LocalDateTime;
import java.util.UUID;

import lombok.ToString;

public record UserDto(

        UUID id,

        String email,

        String fullname,

        LocalDateTime createdAt

) {
}