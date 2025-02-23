package org.myProject.focus_flow_gateway_api.api.factories;

import lombok.NonNull;
import org.myProject.focus_flow_gateway_api.api.dto.UserRequestDto;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Role;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Status;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class UserRequestDtoFactory {

    public UserRequestDto makeUserRequestDto(
            @NonNull String email, @NonNull String password,
            @NonNull String username, @NonNull String telegramLink,
            String status, String role, String profilePicture) {

        return UserRequestDto
                .builder()
                .email(email)
                .password(password)
                .username(username)
                .telegramLink(telegramLink)
                .status(status != null ? Status.valueOf(status) : null)
                .role(role != null ? Role.valueOf(role) : null)
                .profilePicture(profilePicture == null ? "noData.img" : profilePicture)
                .build();
    }
}
