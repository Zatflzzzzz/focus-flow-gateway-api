package org.myProject.focus_flow_gateway_api.api.controllers.helpers;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;
import javax.ws.rs.core.Response;
import java.util.List;

@Slf4j
@Component
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserAuthHelper {

    final Keycloak keycloak;

    @Value("${KEYCLOAK_URL}")
    private String keycloakUrl;

    @Value("${KEYCLOAK_REALM}")
    private String realm;

    @Value("${KEYCLOAK_CLIENT_ID}")
    private String clientId;

    @Value("${KEYCLOAK_CLIENT_SECRET}")
    private String clientSecret;

    public UserAuthHelper(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    public String registerUser(UserRequestDto requestDto) {

        log.info("Registering user: {}", requestDto.getUsername());

        checkIfUserExists(requestDto);

        try {

            UsersResource usersResource = keycloak.realm(realm).users();

            UserRepresentation user = getUserRepresentation(requestDto);
            Response response = usersResource.create(user);
            log.info("Creating user with attributes: {}", user.getAttributes());

            if (response.getStatus() == 201) {
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                log.info("User created successfully with ID: {}", response);

                return userId;
            } else {
                String errorMessage = String.format("Failed to create user: %s", response.getStatusInfo().getReasonPhrase());
                log.error(errorMessage);

                throw new CustomAppException(HttpStatus.BAD_REQUEST, errorMessage);
            }
        } catch (Exception e) {
            log.error("Error while registering user", e);

            throw new CustomAppException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }

    public String authenticate(String username, String password) {
        String tokenUri = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("grant_type", "password");
        requestBody.add("username", username);
        requestBody.add("password", password);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<Map> response = restTemplate.exchange(tokenUri, HttpMethod.POST, requestEntity, Map.class);

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return response.getBody().get("access_token").toString();
        } else {
            throw new RuntimeException("Ошибка аутентификации: " + response.getStatusCode());
        }
    }

    private static UserRepresentation getUserRepresentation(UserRequestDto requestDto) {

        UserRepresentation user = new UserRepresentation();
        user.setUsername(requestDto.getUsername());
        user.setEmail(requestDto.getEmail());
        user.setEnabled(true);

        CredentialRepresentation credential = new CredentialRepresentation();

        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(requestDto.getPassword());
        credential.setTemporary(false);

        user.setCredentials(List.of(credential));
        user.setRealmRoles(Collections.singletonList("ROLE_USER"));

        user.singleAttribute("telegram_link", requestDto.getTelegramLink());
        user.singleAttribute("profile_picture", requestDto.getProfilePicture());
        user.singleAttribute("registration_date", requestDto.getRegistrationDate().toString());

        if (requestDto.getStatus() != null) {
            user.singleAttribute("status", requestDto.getStatus().name());
        }

        return user;
    }

    private void checkIfUserExists(UserRequestDto requestDto) {
        UsersResource usersResource = keycloak.realm(realm).users();

        List<UserRepresentation> usersByUsername = usersResource.search(requestDto.getUsername(), true);
        if (!usersByUsername.isEmpty()) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST,
                    "User with name '" + requestDto.getUsername() + "' already exists");
        }

        List<UserRepresentation> users = usersResource.list(0, 10000);
        boolean emailExists = users.stream()
                .anyMatch(user -> requestDto.getEmail().equalsIgnoreCase(user.getEmail()));

        if (emailExists) {
            throw new CustomAppException(HttpStatus.BAD_REQUEST,
                    "User with email '" + requestDto.getEmail() + "' already exists");
        }
    }


}
