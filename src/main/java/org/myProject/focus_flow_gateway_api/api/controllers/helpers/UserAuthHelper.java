package org.myProject.focus_flow_gateway_api.api.controllers.helpers;

import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.ClientRepresentation;
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
import java.util.*;

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
                // Добавляем небольшую задержку перед назначением роли
                Thread.sleep(500);
                assignRolesToUser(userId);
                log.info("User {} successfully registered with roles", userId);
                return userId;
            } catch (Exception e) {
                usersResource.delete(userId);
                log.error("Failed to assign roles to user {}. User deleted. Error: {}", userId, e.getMessage(), e);
                throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to assign roles to user: " + e.getMessage());
            }
        } else {
            String error = response.readEntity(String.class);
            log.error("Keycloak error response: {}", error);
            throw new CustomAppException(HttpStatus.BAD_REQUEST,
                    "Failed to create user in Keycloak: " + error);
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

        // Инициализируем атрибуты
        Map<String, List<String>> attributes = new HashMap<>();

        attributes.put("telegramLink", List.of(requestDto.getTelegramLink()));

        if (requestDto.getRegistrationDate() != null) {
            attributes.put("registrationDate", List.of(requestDto.getRegistrationDate().toString()));
        }

        if (requestDto.getStatus() != null) {
            attributes.put("status", List.of(String.valueOf(requestDto.getStatus())));
        }

        user.setAttributes(attributes);
        return user;
    }

    private void checkIfUserExists(UserRequestDto requestDto) {
        UsersResource usersResource = keycloak.realm(realm).users();
        List<UserRepresentation> users = usersResource.search(requestDto.getUsername(), true);

        if (!users.isEmpty() || usersResource.list().stream().anyMatch(u ->
                requestDto.getEmail().equalsIgnoreCase(u.getEmail()))) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST,
                    "User with this username or email already exists");
        }
    }

    private String extractUserId(Response response) {
        String location = response.getLocation().toString();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private void assignRolesToUser(String userId) {
        try {
            UsersResource usersResource = keycloak.realm(realm).users();
            UserResource userResource = usersResource.get(userId);

            if (userResource == null) {
                throw new CustomAppException(HttpStatus.NOT_FOUND,
                        "User with ID " + userId + " not found in Keycloak.");
            }

            // Получаем роль из realm
            RoleResource roleResource = keycloak.realm(realm).roles().get(Role.USER.name());
            RoleRepresentation roleRepresentation = roleResource.toRepresentation();

            // Назначаем роль
            userResource.roles().realmLevel().add(Collections.singletonList(roleRepresentation));

            log.info("Role {} successfully assigned to user {}", Role.USER, userId);
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}: {}", Role.USER.name(), userId, e.getMessage(), e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error assigning role: " + e.getMessage());
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

    public void updateUser(String userId, String email, String password, String username,
                           String firstName, String lastName, String telegramLink,
                           String status, String token, boolean isAdminUpdate) {

        // Проверяем права доступа
        String currentUserId = getUserIdFromToken(token);

        if (!isAdminUpdate && !currentUserId.equals(userId)) {
            throw new CustomAppException(HttpStatus.FORBIDDEN, "You can only update your own profile");
        }

        if (isAdminUpdate && !isAdmin(token)) {
            throw new CustomAppException(HttpStatus.FORBIDDEN, "Admin privileges required");
        }

        UserResource userResource = keycloak.realm(realm).users().get(userId);
        UserRepresentation user = Optional.ofNullable(userResource.toRepresentation())
                .orElseThrow(() -> new CustomAppException(HttpStatus.NOT_FOUND, "User not found"));

        if (email != null) user.setEmail(email);
        if (username != null) user.setUsername(username);
        if (firstName != null) user.setFirstName(firstName);
        if (lastName != null) user.setLastName(lastName);

        // Обновляем атрибуты
        Map<String, List<String>> attributes = Optional.ofNullable(user.getAttributes())
                .orElse(new HashMap<>());

        if (telegramLink != null) {
            attributes.put("telegramLink", Collections.singletonList(telegramLink));
        }

        // Только админ может обновлять эти поля
        if (isAdminUpdate) {
            if (status != null) {
                attributes.put("status", Collections.singletonList(status));
            }
        }

        user.setAttributes(attributes);

        // Обновление пароля
        if (password != null) {
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(password);
            credential.setTemporary(false);
            user.setCredentials(Collections.singletonList(credential));
        }

        userResource.update(user);
        log.info("User {} updated by {}", userId, isAdminUpdate ? "admin" : "user");
    }

    public String getCurrentUserId(String token) {
        return getUserIdFromToken(token);
    }

    public void logout(String authHeader) {
        String accessToken = extractAccessToken(authHeader);

        try {
            webClient.post()
                    .uri(keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/logout")
                    .header("Authorization", "Bearer " + accessToken)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .bodyValue(createLogoutForm())
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, response -> {
                        log.error("Logout failed with status {}", response.statusCode());
                        return Mono.error(new CustomAppException(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Logout failed with status: " + response.statusCode()
                        ));
                    })
                    .bodyToMono(Void.class)
                    .block();
        } catch (Exception e) {
            log.error("Logout failed", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Logout failed: " + e.getMessage());
        }
    }

    private String extractAccessToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Invalid authorization header");
        }
        return authHeader.substring(7);
    }

    private MultiValueMap<String, String> createLogoutForm() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        return form;
    }

    public UserRepresentation getUserById(String userId, String token) {
        validateUserAccess(userId, token);
        return Optional.ofNullable(keycloak.realm(realm).users().get(userId).toRepresentation())
                .orElseThrow(() -> new CustomAppException(HttpStatus.NOT_FOUND, "User not found"));
    }

    public List<UserRepresentation> getAllUsers(String token) {
        validateAdminAccess(token);
        return keycloak.realm(realm).users().list();
    }

    private void validateAdminAccess(String token) {
        if (!isAdmin(token)) {
            throw new CustomAppException(HttpStatus.FORBIDDEN, "Admin access required");
        }
    }

    private void validateUserAccess(String requestedUserId, String token) {
        if (!isAdmin(token) && !getUserIdFromToken(token).equals(requestedUserId)) {
            throw new CustomAppException(HttpStatus.FORBIDDEN, "Access denied");
        }
    }

    private boolean isAdmin(String token) {
        String userId = getUserIdFromToken(token);
        UserResource userResource = keycloak.realm(realm).users().get(userId);

        // Проверка realm-level ролей
        List<RoleRepresentation> realmRoles = userResource.roles().realmLevel().listEffective();
        boolean hasRealmAdmin = realmRoles.stream().anyMatch(r -> r.getName().equals(Role.ADMIN.name()));

        ClientsResource clientsResource = keycloak.realm(realm).clients();
        Optional<ClientRepresentation> clientRep = clientsResource.findByClientId(clientId).stream().findFirst();

        if (clientRep.isEmpty()) {
            log.error("Client {} not found in Keycloak", clientId);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Client not found");
        }

        String clientUuid = clientRep.get().getId();
        List<RoleRepresentation> clientRoles = userResource.roles().clientLevel(clientUuid).listEffective();
        boolean hasClientAdmin = clientRoles.stream().anyMatch(r -> r.getName().equals(Role.ADMIN.name()));

        return hasRealmAdmin || hasClientAdmin;
    }

    public String getUserIdFromToken(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Invalid authorization header format");
        }

        String jwtToken = token.substring(7).trim();

        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);
            return signedJWT.getJWTClaimsSet().getSubject(); // "sub"
        } catch (Exception e) {
            log.error("Failed to parse JWT", e);
            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Invalid JWT token");
        }
    }
}