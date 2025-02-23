package org.myProject.focus_flow_gateway_api.api.controllers;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.myProject.focus_flow_gateway_api.api.controllers.helpers.UserAuthHelper;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.myProject.focus_flow_gateway_api.api.factories.UserRequestDtoFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserAuthController {

    UserRequestDtoFactory userRequestDtoFactory;
    UserAuthHelper userAuthHelper;

    public static final String REGISTER = "/api/register";
    public static final String LOGIN = "/api/login";

    @PostMapping(REGISTER)
    public ResponseEntity<?> registerUser(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String username,
            @RequestParam(name = "telegram_link", required = false) String telegramLink,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String role,
            @RequestParam(value = "profile_picture", required = false) String profilePicture) {

        validateRegistrationInput(email, password, username, telegramLink);

        UserRequestDto user = userRequestDtoFactory
                .makeUserRequestDto(email, password, username, telegramLink, status, role, profilePicture);

        String userId = userAuthHelper.registerUser(user);

        log.info(String.valueOf(user));

        return ResponseEntity.ok(Collections.singletonMap("userId", userId));
    }

    @PostMapping(LOGIN)
    public ResponseEntity<?> authenticate(
            @RequestParam String username,
            @RequestParam String password) {

        validateLoginInput(username, password);

        try {
            String token = userAuthHelper.authenticate(username, password);
            return ResponseEntity.ok().body(Map.of("access_token", token));
        } catch (Exception e) {
            log.error("Ошибка аутентификации", e);
            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Ошибка аутентификации: " + e.getMessage());
        }
    }

    private void validateRegistrationInput(String email, String password, String username, String telegramLink) {
        if (email == null || email.isBlank() || !email.contains("@")) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Некорректный email");
        }
        if (password == null || password.length() < 6) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Пароль должен содержать не менее 6 символов");
        }
        if (username == null || username.isBlank()) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Имя пользователя не может быть пустым");
        }
        if (telegramLink == null || telegramLink.isBlank()) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Ссылка на Telegram не может быть пустой");
        }
    }

    private void validateLoginInput(String username, String password) {
        if (username == null || username.isBlank()) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Имя пользователя не может быть пустым");
        }
        if (password == null || password.isBlank()) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Пароль не может быть пустым");
        }
    }
}
