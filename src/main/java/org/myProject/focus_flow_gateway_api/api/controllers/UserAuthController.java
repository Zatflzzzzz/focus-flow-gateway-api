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
import reactor.core.publisher.Mono;

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
    public Mono<ResponseEntity<Map<String, String>>> registerUser(
            @RequestParam String email,
            @RequestParam String password,
            @RequestParam String username,
            @RequestParam("first_name") String firstName,
            @RequestParam("last_name") String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink) {

        UserRequestDto user = userRequestDtoFactory
                .makeUserRequestDto(email, password, username, telegramLink, firstName, lastName);

        return Mono.fromCallable(() -> {
                    try {
                        String userId = userAuthHelper.registerUser(user);
                        log.info("User registered: {}", user);
                        return ResponseEntity.ok(Collections.singletonMap("userId", userId));
                    } catch (Exception e) {
                        log.error("Registration failed for user: {}", user, e);
                        throw new CustomAppException(HttpStatus.BAD_REQUEST,
                                "Registration failed: " + e.getMessage());
                    }
                })
                .onErrorResume(e -> {
                    if (e instanceof CustomAppException) {
                        return Mono.error(e);
                    }
                    return Mono.error(new CustomAppException(
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "Internal server error during registration"));
                });
    }

    @PostMapping(LOGIN)
    public Mono<ResponseEntity<Map<String, Object>>> authenticate(
            @RequestParam String username,
            @RequestParam String password) {

        return Mono.fromCallable(() -> userAuthHelper.authenticate(username, password))
                .map(ResponseEntity::ok)
                .onErrorResume(e -> {
                    log.error("Authentication error", e);
                    return Mono.error(new CustomAppException(HttpStatus.UNAUTHORIZED, "Ошибка аутентификации: " + e.getMessage()));
                });
    }

    @PostMapping(REFRESH_TOKEN)
    public Mono<ResponseEntity<Map<String, Object>>> refreshToken(@RequestParam("refresh_token") String refreshToken) {
        return Mono.fromCallable(() -> userAuthHelper.refreshToken(refreshToken))
                .map(ResponseEntity::ok)
                .onErrorResume(e -> {
                    log.error("Refresh token error", e);
                    return Mono.error(new CustomAppException(HttpStatus.UNAUTHORIZED, "Ошибка обновления токена: " + e.getMessage()));
                });
    }

    @PutMapping(UPDATE_CURRENT_USER_DATA)
    public Mono<ResponseEntity<Map<String, String>>> updateCurrentUser(
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String username,
            @RequestParam(value = "first_name", required = false) String firstName,
            @RequestParam(value = "last_name", required = false) String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink,
            @RequestHeader("Authorization") String token) {

        return Mono.fromCallable(() -> {
                    String userId = userAuthHelper.getCurrentUserId(token);
                    userAuthHelper.updateUser(
                            userId, email, password, username, firstName, lastName,
                            telegramLink, null, token, false);
                    return ResponseEntity.ok(Collections.singletonMap("message", "User data updated successfully"));
                })
                .onErrorResume(e -> {
                    log.error("Error updating user data", e);
                    return Mono.error(e);
                });
    }

    @PutMapping(UPDATE_USER_DATA)
    public Mono<ResponseEntity<Map<String, String>>> updateUserByAdmin(
            @RequestParam("user_id") String userId,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String username,
            @RequestParam(value = "first_name", required = false) String firstName,
            @RequestParam(value = "last_name", required = false) String lastName,
            @RequestParam(name = "telegram_link", required = false) String telegramLink,
            @RequestParam(required = false) String status,
            @RequestHeader("Authorization") String token) {

        return Mono.fromCallable(() -> {
                    userAuthHelper.updateUser(
                            userId, email, password, username, firstName, lastName,
                            telegramLink, status, token, true);
                    return ResponseEntity.ok(Collections.singletonMap("message", "User data updated by admin successfully"));
                })
                .onErrorResume(e -> {
                    log.error("Admin update error", e);
                    return Mono.error(e);
                });
    }

    @PostMapping(LOGOUT_USER)
    public Mono<ResponseEntity<Map<String, String>>> logout(
            @RequestHeader("Authorization") String authHeader) {

        return Mono.fromRunnable(() -> userAuthHelper.logout(authHeader))
                .thenReturn(ResponseEntity.ok(Collections.singletonMap("message", "Successfully logged out")))
                .onErrorResume(e -> {
                    log.error("Logout error", e);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Collections.singletonMap("error", e.getMessage())));
                });
    }

    @GetMapping(GET_USER_INFO)
    public Mono<ResponseEntity<UserRepresentation>> getUserById(
            @PathVariable(name = "user_id") String userId,
            @RequestHeader("Authorization") String token) {

        return Mono.fromCallable(() -> ResponseEntity.ok(userAuthHelper.getUserById(userId, token)))
                .onErrorResume(e -> {
                    log.error("Get user by ID error", e);
                    return Mono.error(e);
                });
    }

    @GetMapping(GET_USERS_INFO)
    public Mono<ResponseEntity<List<UserRepresentation>>> getAllUsers(
            @RequestHeader("Authorization") String token) {

        return Mono.fromCallable(() -> ResponseEntity.ok(userAuthHelper.getAllUsers(token)))
                .onErrorResume(e -> {
                    log.error("Get all users error", e);
                    return Mono.error(e);
                });
    }
}