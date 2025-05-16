package org.myProject.focus_flow_gateway_api.api.factories;

import lombok.NonNull;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Role;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Status;
import org.springframework.stereotype.Component;

@Component
public class UserRequestDtoFactory {

    public UserRequestDto makeUserRequestDto(
            @NonNull String email, @NonNull String password,
            @NonNull String username, @NonNull String telegramLink,
            @NonNull String firstName, @NonNull String lastName,
            String status, String role, String profilePicture) {

        return UserRequestDto
                .builder()
                .email(email)
                .password(password)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .telegramLink(telegramLink)
                .status(status != null ? Status.valueOf(status) : null)
                .role(Role.valueOf("USER"))
                .profilePicture(profilePicture == null ? "noData.img" : profilePicture)
                .build();
    }
}
