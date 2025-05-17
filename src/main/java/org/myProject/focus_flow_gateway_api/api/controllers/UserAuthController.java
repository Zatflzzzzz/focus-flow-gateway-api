package org.myProject.focus_flow_gateway_api.api.controllers;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.UserRepresentation;
import org.myProject.focus_flow_gateway_api.api.controllers.helpers.UserAuthHelper;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.myProject.focus_flow_gateway_api.api.factories.UserRequestDtoFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
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
    public static final String UPDATE_USER_DATA = "/api/admin/update_user_data";
    private static final String UPDATE_CURRENT_USER_DATA = "/api/update_current_user_data";
    public static final String LOGOUT_USER = "/api/logout";
    public static final String GET_USER_INFO = "/api/users/{user_id}";
    public static final String GET_USERS_INFO = "/api/admin/users";

    @PostMapping(REGISTER)
    public ResponseEntity<?> registerUser(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String username,
            @RequestParam("first_name") String firstName,
            @RequestParam("last_name") String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink ) {

        //TODO сделать валидацию данных

        UserRequestDto user = userRequestDtoFactory
                .makeUserRequestDto(email, password, username, telegramLink, firstName, lastName);

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

    @PutMapping(UPDATE_CURRENT_USER_DATA)
    public ResponseEntity<Map<String, String>> updateCurrentUser(
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String username,
            @RequestParam(value = "first_name", required = false) String firstName,
            @RequestParam(value = "last_name", required = false) String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink,
            @RequestHeader("Authorization") String token) {

        log.debug("Received token: {}", token); // Логируем полученный токен
        try {
            String userId = userAuthHelper.getCurrentUserId(token);
            log.debug("Extracted user ID: {}", userId);

            userAuthHelper.updateUser(
                    userId, email, password, username, firstName, lastName,
                    telegramLink, null, token, false);
            return ResponseEntity.ok(Collections.singletonMap("message", "User data updated successfully"));
        } catch (Exception e) {
            log.error("Error updating user data", e);
            throw e;
        }
    }

    @PutMapping(UPDATE_USER_DATA)
    public ResponseEntity<Map<String, String>> updateUserByAdmin(
            @RequestParam("user_id") String userId,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String username,
            @RequestParam(value = "first_name", required = false) String firstName,
            @RequestParam(value = "last_name", required = false) String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink,
            @RequestParam(required = false) String status,
            @RequestHeader("Authorization") String token) {

        userAuthHelper.updateUser(
                userId, email, password, username, firstName, lastName,
                telegramLink, status, token, true);
        return ResponseEntity.ok(Collections.singletonMap("message", "User data updated by admin successfully"));
    }


    @PostMapping(LOGOUT_USER)
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader("Authorization") String authHeader) {

        userAuthHelper.logout(authHeader);
        return ResponseEntity.ok(Collections.singletonMap("message", "Successfully logged out"));
    }

    @GetMapping(GET_USER_INFO)
    public ResponseEntity<UserRepresentation> getUserById(
            @PathVariable(name = "user_id") String userId,
            @RequestHeader("Authorization") String token) {

        return ResponseEntity.ok(userAuthHelper.getUserById(userId, token));
    }

    @GetMapping(GET_USERS_INFO)
    public ResponseEntity<List<UserRepresentation>> getAllUsers(
            @RequestHeader("Authorization") String token) {

        return ResponseEntity.ok(userAuthHelper.getAllUsers(token));
    }
}
