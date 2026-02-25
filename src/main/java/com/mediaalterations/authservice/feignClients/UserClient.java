package com.mediaalterations.authservice.feignClients;

import com.mediaalterations.authservice.dto.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "user-service", path = "/user", url = "${services.user-service.url}")
public interface UserClient {

    @PostMapping("/add")
    public ResponseEntity<UserDto> add(@RequestBody UserDto userDto);

    @GetMapping
    public ResponseEntity<UserDto> getUser(@RequestHeader("user_id") String userId);

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable("id") String id);

}
