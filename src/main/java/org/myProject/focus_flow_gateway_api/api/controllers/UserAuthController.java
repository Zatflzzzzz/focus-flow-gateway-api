package org.myProject.focus_flow_gateway_api.api.controllers;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.myProject.focus_flow_gateway_api.api.controllers.helpers.UserAuthHelper;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.factories.UserRequestDtoFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Collections;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserAuthController {

    UserRequestDtoFactory userRequestDtoFactory;

    private final UserAuthHelper userAuthHelper;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String username,
            @RequestParam("telegram_link") String telegramLink,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String role,
            @RequestParam(value = "profile_picture", required = false) String profilePicture) {

        UserRequestDto user = userRequestDtoFactory
                .makeUserRequestDto(email, password, username, telegramLink, status, role, profilePicture);

        String userId = userAuthHelper.registerUser(user);

        return ResponseEntity.ok(Collections.singletonMap("userId", userId));
    }
}