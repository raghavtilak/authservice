package com.mediaalterations.authservice.feignClients;

import com.mediaalterations.authservice.dto.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", url = "${services.user-service.url}")
public interface UserClient {

    @PostMapping("/user/add")
    public ResponseEntity<UserDto> add(@RequestBody UserDto userDto);
}
