package org.myProject.focus_flow_gateway_api.api.controllers.helpers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.*;
import org.myProject.focus_flow_gateway_api.api.controllers.helpers.util.HttpHelper;
import org.myProject.focus_flow_gateway_api.api.controllers.helpers.util.HttpResponse;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Role;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@FieldDefaults(level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class UserAuthHelper {

    @Value("${KEYCLOAK_URL}")
    String keycloakUrl;

    @Value("${KEYCLOAK_REALM}")
    String realm;

    @Value("${KEYCLOAK_CLIENT_ID}")
    String clientId;

    @Value("${KEYCLOAK_CLIENT_SECRET}")
    String clientSecret;

    private final ObjectMapper objectMapper;
    private String adminToken;

    @PostConstruct
    public void init() {
        try {
            this.adminToken = getAdminToken();
            log.info("Admin token successfully obtained");
        } catch (Exception e) {
            log.error("Critical error during admin token initialization", e);
            throw new RuntimeException("Application startup failed due to authentication issues");
        }
    }

    private String getAdminToken() {
        try {
            // Исправленный URL для текущего realm
            String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

            // Используем client_id из конфигурации приложения
            String requestBody = "grant_type=client_credentials" +
                    "&client_id=" + clientId +
                    "&client_secret=" + clientSecret;

            HttpResponse response = HttpHelper.sendHttpRequest(tokenUrl, "POST", requestBody,
                    "application/x-www-form-urlencoded", null);

            Map<String, Object> tokenData = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
            return (String) tokenData.get("access_token");

        } catch (Exception e) {
            log.error("Failed to get admin token", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to initialize admin access");
        }
    }

    public String registerUser(UserRequestDto requestDto) {
        log.info("Registering user: {}", requestDto.getUsername());
        checkIfUserExists(requestDto);

        String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";
        UserRepresentation user = createUserRepresentation(requestDto);

        try {
            HttpResponse response = HttpHelper.sendHttpRequest(usersUrl, "POST", objectMapper.writeValueAsString(user),
                    "application/json", adminToken);

            List<String> locationList = response.getHeaders().get("Location");
            if (locationList == null || locationList.isEmpty()) {
                throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "User created but no location header returned");
            }

            String location = locationList.get(0);
            String userId = location.substring(location.lastIndexOf('/') + 1);

            Thread.sleep(500); // небольшая задержка перед назначением роли
            assignRolesToUser(userId);
            return userId;

        } catch (Exception e) {
            log.error("Failed to register user", e);
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Failed to register user: " + e.getMessage());
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
        String searchUrl = keycloakUrl + "/admin/realms/" + realm + "/users?username=" +
                requestDto.getUsername() + "&exact=true";

        try {
            List<UserRepresentation> users = sendHttpRequest(searchUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<UserRepresentation>>() {});

            if (!users.isEmpty()) {
                throw new CustomAppException(HttpStatus.BAD_REQUEST,
                        "User with this username already exists");
            }

            // Проверка по email
            searchUrl = keycloakUrl + "/admin/realms/" + realm + "/users?email=" + requestDto.getEmail();
            users = sendHttpRequest(searchUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<UserRepresentation>>() {});

            if (!users.isEmpty()) {
                throw new CustomAppException(HttpStatus.BAD_REQUEST,
                        "User with this email already exists");
            }
        } catch (CustomAppException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error checking user existence", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error checking user existence: " + e.getMessage());
        }
    }

    private void assignRolesToUser(String userId) {
        try {
            // First check if the role exists
            String rolesUrl = keycloakUrl + "/admin/realms/" + realm + "/roles";
            List<RoleRepresentation> availableRoles = sendHttpRequest(rolesUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<RoleRepresentation>>() {});

            Optional<RoleRepresentation> userRole = availableRoles.stream()
                    .filter(r -> r.getName().equals(Role.USER.name()))
                    .findFirst();

            if (userRole.isEmpty()) {
                throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Role " + Role.USER.name() + " not found in Keycloak");
            }

            // Assign the role to user
            String userRolesUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";

            HttpResponse response = HttpHelper.sendHttpRequest(
                    userRolesUrl,
                    "POST",
                    objectMapper.writeValueAsString(List.of(userRole.get())),
                    "application/json",
                    adminToken
            );

            if (response.getStatusCode() >= 400) {
                throw new CustomAppException(HttpStatus.valueOf(response.getStatusCode()),
                        "Failed to assign role: " + response.getBody());
            }

            log.info("Role {} successfully assigned to user {}", Role.USER, userId);
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}: {}", Role.USER.name(), userId, e.getMessage(), e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error assigning role: " + e.getMessage());
        }
    }

    public Map<String, Object> authenticate(String username, String password) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        String requestBody = "client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&grant_type=password" +
                "&username=" + username +
                "&password=" + password;

        try {
            Map<String, Object> response = sendHttpRequest(tokenUrl, "POST", requestBody,
                    "application/x-www-form-urlencoded", null);
            return extractTokenData(response);
        } catch (Exception e) {
            log.error("Authentication failed", e);
            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Authentication failed: " + e.getMessage());
        }
    }

    public Map<String, Object> refreshToken(String refreshToken) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        String requestBody = "client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&grant_type=refresh_token" +
                "&refresh_token=" + refreshToken;

        try {
            Map<String, Object> response = sendHttpRequest(tokenUrl, "POST", requestBody,
                    "application/x-www-form-urlencoded", null);
            return extractTokenData(response);
        } catch (Exception e) {
            log.error("Token refresh failed", e);
            throw new CustomAppException(HttpStatus.UNAUTHORIZED, "Token refresh failed: " + e.getMessage());
        }
    }

    private Map<String, Object> extractTokenData(Map<String, Object> response) {
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

        try {
            // Получаем текущие данные пользователя
            String userUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
            UserRepresentation user = sendHttpRequest(userUrl, "GET", null,
                    "application/json", adminToken, UserRepresentation.class);

            if (user == null) {
                throw new CustomAppException(HttpStatus.NOT_FOUND, "User not found");
            }

            // Обновляем поля
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
            if (isAdminUpdate && status != null) {
                attributes.put("status", Collections.singletonList(status));
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

            // Отправляем обновленные данные
            sendHttpRequest(userUrl, "PUT", objectMapper.writeValueAsString(user),
                    "application/json", adminToken);

            log.info("User {} updated by {}", userId, isAdminUpdate ? "admin" : "user");
        } catch (Exception e) {
            log.error("Error updating user", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error updating user: " + e.getMessage());
        }
    }

    public String getCurrentUserId(String token) {
        return getUserIdFromToken(token);
    }

    public void logout(String authHeader) {
        String accessToken = extractAccessToken(authHeader);
        String logoutUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        String requestBody = "client_id=" + clientId + "&client_secret=" + clientSecret;

        try {
            sendHttpRequest(logoutUrl, "POST", requestBody,
                    "application/x-www-form-urlencoded", accessToken);
        } catch (Exception e) {
            log.error("Logout failed", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Logout failed: " + e.getMessage());
        }
    }

    private String extractAccessToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST, "Invalid authorization header");
        }
        return authHeader.substring(7);
    }

    public UserRepresentation getUserById(String userId, String token) {
        validateUserAccess(userId, token);

        try {
            String userUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId;
            return sendHttpRequest(userUrl, "GET", null,
                    "application/json", adminToken, UserRepresentation.class);
        } catch (Exception e) {
            log.error("Error getting user by id", e);
            throw new CustomAppException(HttpStatus.NOT_FOUND, "User not found");
        }
    }

    public List<UserRepresentation> getAllUsers(String token) {
        validateAdminAccess(token);

        try {
            String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";
            return sendHttpRequest(usersUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<UserRepresentation>>() {});
        } catch (Exception e) {
            log.error("Error getting all users", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error getting users: " + e.getMessage());
        }
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

        try {
            // Проверяем realm-level роли
            String realmRolesUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";
            List<RoleRepresentation> realmRoles = sendHttpRequest(realmRolesUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<RoleRepresentation>>() {});

            boolean hasRealmAdmin = realmRoles.stream()
                    .anyMatch(r -> r.getName().equals(Role.ADMIN.name()));

            // Проверяем client-level роли
            String clientsUrl = keycloakUrl + "/admin/realms/" + realm + "/clients?clientId=" + clientId;
            List<ClientRepresentation> clients = sendHttpRequest(clientsUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<ClientRepresentation>>() {});

            if (clients.isEmpty()) {
                log.error("Client {} not found in Keycloak", clientId);
                throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Client not found");
            }

            String clientUuid = clients.get(0).getId();
            String clientRolesUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + userId +
                    "/role-mappings/clients/" + clientUuid;

            List<RoleRepresentation> clientRoles = sendHttpRequest(clientRolesUrl, "GET", null,
                    "application/json", adminToken, new TypeReference<List<RoleRepresentation>>() {});

            boolean hasClientAdmin = clientRoles.stream()
                    .anyMatch(r -> r.getName().equals(Role.ADMIN.name()));

            return hasRealmAdmin || hasClientAdmin;
        } catch (Exception e) {
            log.error("Error checking admin privileges", e);
            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Error checking admin privileges: " + e.getMessage());
        }
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

    // Общий метод для отправки HTTP запросов
    private <T> T sendHttpRequest(String urlString, String method, String requestBody,
                                  String contentType, String authToken, TypeReference<T> typeRef) throws Exception {
        HttpResponse response = HttpHelper.sendHttpRequest(urlString, method, requestBody, contentType, authToken);
        return objectMapper.readValue(response.getBody(), typeRef);
    }

    private <T> T sendHttpRequest(String urlString, String method, String requestBody,
                                  String contentType, String authToken, Class<T> responseType) throws Exception {
        HttpResponse response = HttpHelper.sendHttpRequest(urlString, method, requestBody, contentType, authToken);
        return objectMapper.readValue(response.getBody(), responseType);
    }

    private Map<String, Object> sendHttpRequest(String urlString, String method, String requestBody,
                                                String contentType, String authToken) throws Exception {
        HttpResponse response = HttpHelper.sendHttpRequest(urlString, method, requestBody, contentType, authToken);
        return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    }

    private String sendHttpRequestRaw(String urlString, String method, String requestBody,
                                      String contentType, String authToken) throws Exception {
        return HttpHelper.sendHttpRequest(urlString, method, requestBody, contentType, authToken).getBody();
    }


    private String readErrorResponse(HttpURLConnection connection) throws IOException {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(connection.getErrorStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            return response.toString();
        }
    }

    private String getResponseHeader(String headerName) {
        // Этот метод нужно реализовать, если требуется доступ к заголовкам ответа
        // В текущей реализации он не используется, но оставлен для будущих расширений
        return null;
    }
}