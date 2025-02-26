package org.myProject.focus_flow_gateway_api.api.controllers.helpers;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Role;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@FieldDefaults(level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class UserAuthHelper {

    final Keycloak keycloak;
    final WebClient webClient;

    @Value("${KEYCLOAK_URL}")
    String keycloakUrl;

    @Value("${KEYCLOAK_REALM}")
    String realm;

    @Value("${KEYCLOAK_CLIENT_ID}")
    String clientId;

    @Value("${KEYCLOAK_CLIENT_SECRET}")
    String clientSecret;

    public String registerUser(UserRequestDto requestDto) {
        log.info("Registering user: {}", requestDto.getUsername());
        checkIfUserExists(requestDto);

        UsersResource usersResource = keycloak.realm(realm).users();
        UserRepresentation user = createUserRepresentation(requestDto);
        Response response = usersResource.create(user);

        if (response.getStatus() == 201) {
            String userId = extractUserId(response);

            try {
                assignRolesToUser(userId, requestDto.getRole());
                log.info("User {} successfully registered with roles", userId);

                return userId;
            } catch (Exception e) {
                usersResource.delete(userId);
                log.error("Failed to assign roles to user {}. User deleted.", userId, e);

                throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to assign roles to user.");
            }
        } else {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Failed to create user: " + response.getStatusInfo().getReasonPhrase());
        }
    }

    private UserRepresentation createUserRepresentation(UserRequestDto requestDto) {

        UserRepresentation user = new UserRepresentation();
        user.setUsername(requestDto.getUsername());
        user.setEmail(requestDto.getEmail());
        user.setFirstName(requestDto.getFirstName());
        user.setLastName(requestDto.getLastName());
        user.setEnabled(true);

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(requestDto.getPassword());
        credential.setTemporary(false);
        user.setCredentials(List.of(credential));

        user.setAttributes(Map.of(
                "telegramLink", List.of(requestDto.getTelegramLink()),
                "profilePicture", List.of(requestDto.getProfilePicture()),
                "registrationDate", List.of(requestDto.getRegistrationDate().toString())
        ));

        if (requestDto.getStatus() != null) {
            user.getAttributes().put("status", List.of(requestDto.getStatus().name()));
        }

        return user;
    }

    private void checkIfUserExists(UserRequestDto requestDto) {

        UsersResource usersResource = keycloak.realm(realm).users();
        List<UserRepresentation> users = usersResource.search(requestDto.getUsername(), true);

        if (!users.isEmpty() || usersResource.list().stream().anyMatch(u -> requestDto.getEmail().equalsIgnoreCase(u.getEmail()))) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "User with this username or email already exists");
        }
    }

    private String extractUserId(Response response) {
        String location = response.getLocation().toString();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private void assignRolesToUser(String userId, Role role) {

        if (role == null) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Role cannot be null.");
        }

        try {
            UsersResource usersResource = keycloak.realm(realm).users();

            // Проверяем существование пользователя
            UserResource userResource = usersResource.get(userId);
            if (userResource == null) {
                throw new CustomAppException(HttpStatus.NOT_FOUND, "User with ID " + userId + " not found in Keycloak.");
            }

            // Проверяем существование роли
            RoleResource roleResource = keycloak.realm(realm).roles().get(role.name());
            if (roleResource == null) {
                throw new CustomAppException(HttpStatus.NOT_FOUND, "Role " + role.name() + " not found in Keycloak.");
            }

            RoleRepresentation roleRepresentation = roleResource.toRepresentation();
            if (roleRepresentation == null) {
                throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Role representation for " + role.name() + " is null.");
            }

            // Назначаем роль
            userResource.roles().realmLevel().add(Collections.singletonList(roleRepresentation));
            log.info("Successfully assigned role {} to user {}", role.name(), userId);

        } catch (CustomAppException e) {
            log.error("Custom error: {}", e.getMessage());

            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while assigning role {} to user {}: {}", role.name(), userId, e.getMessage(), e);

            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error while assigning role.");
        }
    }

    public Map<String, Object> authenticate(String username, String password) {

        String tokenUri = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        return webClient.post()
                .uri(tokenUri)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(createAuthRequestBody(username, password))
                .retrieve()
                .onStatus(
                        HttpStatusCode::isError,
                        response -> Mono.error(new RuntimeException("Authentication failed: " + response.statusCode()))
                ).bodyToMono(Map.class)
                .map(UserAuthHelper::extractTokenData)
                .block();
    }

    private MultiValueMap<String, String> createAuthRequestBody(String username, String password) {

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("grant_type", "password");
        body.add("username", username);
        body.add("password", password);

        return body;
    }

    public Map<String, Object> refreshToken(String refreshToken) {

        String tokenUri = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        return webClient.post()
                .uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(createRefreshTokenRequestBody(refreshToken))
                .retrieve()
                .onStatus(
                        HttpStatusCode::isError,
                        response -> Mono.error(new RuntimeException("Token refresh failed: " + response.statusCode()))
                ).bodyToMono(Map.class)
                .map(UserAuthHelper::extractTokenData)
                .block();
    }

    private MultiValueMap<String, String> createRefreshTokenRequestBody(String refreshToken) {

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);
        return body;
    }

    private static Map<String, Object> extractTokenData(Map response) {

        Map<String, Object> result = new HashMap<>();
        result.put("access_token", response.get("access_token"));
        result.put("expires_in", response.get("expires_in"));
        result.put("refresh_expires_in", response.get("refresh_expires_in"));
        result.put("refresh_token", response.get("refresh_token"));
        return result;
    }
}