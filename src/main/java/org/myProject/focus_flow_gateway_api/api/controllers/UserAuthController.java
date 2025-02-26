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
import org.springframework.web.bind.annotation.*;

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
    public static final String REFRESH_TOKEN = "/api/refresh_token";

    @PostMapping(REGISTER)
    public ResponseEntity<?> registerUser(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String username,
            @RequestParam("first_name") String firstName,
            @RequestParam("last_name") String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink,
            @RequestParam(required = false) String status,
            @RequestParam(value = "profile_picture", required = false) String profilePicture) {

        //TODO сделать валидацию данных

        UserRequestDto user = userRequestDtoFactory
                .makeUserRequestDto(email, password, username, telegramLink, firstName, lastName, status, null, profilePicture);

        String userId = userAuthHelper.registerUser(user);
        log.info(String.valueOf(user));

        return ResponseEntity.ok(Collections.singletonMap("userId", userId));
    }

    @PostMapping(LOGIN)
    public ResponseEntity<?> authenticate(
            @RequestParam String username,
            @RequestParam String password) {

        try {
            Map<String, Object> token = userAuthHelper.authenticate(username, password);

            return ResponseEntity.ok().body(Map.of("access_token", token));
        } catch (Exception e) {
            log.error("Ошибка аутентификации", e);

            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Ошибка аутентификации: " + e.getMessage());
        }
    }

    @PostMapping(REFRESH_TOKEN)
    public ResponseEntity<?> refreshToken(@RequestParam("refresh_token") String refreshToken) {
        try {
            Map<String, Object> token = userAuthHelper.refreshToken(refreshToken);
            return ResponseEntity.ok().body(Map.of("access_token", token));
        } catch (Exception e) {
            log.error("Ошибка обновления токена", e);
            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Ошибка обновления токена: " + e.getMessage());
        }
    }

    @GetMapping("/text")
    public String text(){
        return "text";
    }
}
