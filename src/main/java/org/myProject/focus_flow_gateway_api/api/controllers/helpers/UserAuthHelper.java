package org.myProject.focus_flow_gateway_api.api.controllers.helpers;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.exceptions.CustomAppException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.Response;
import java.util.List;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserAuthHelper {

    Keycloak keycloak;

    @Value("${keycloak.realm}")
    String realm;

    public String registerUser(UserRequestDto requestDto){

        UsersResource usersResource = keycloak.realm(realm).users();

        UserRepresentation user = getUserRepresentation(requestDto);

        Response response = usersResource.create(user);

        if (response.getStatus() == 201) {

            String userId;

            userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

            return userId;

        } else {
            throw new CustomAppException(HttpStatus.BAD_REQUEST,
                    String.format("Failed to create user" + response.getStatusInfo().getReasonPhrase()));
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

        if (requestDto.getRole() != null) {
            user.setRealmRoles(List.of(requestDto.getRole().name()));
        }

        user.singleAttribute("telegram_link", requestDto.getTelegramLink());
        user.singleAttribute("profile_picture", requestDto.getProfilePicture());
        user.singleAttribute("registration_date", requestDto.getRegistrationDate().toString());

        if (requestDto.getStatus() != null) {
            user.singleAttribute("status", requestDto.getStatus().name());
        }

        return user;
    }
}
