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
            @NonNull String username, String telegramLink,
            @NonNull String firstName, @NonNull String lastName) {

        return UserRequestDto
                .builder()
                .email(email)
                .password(password)
                .username(username)
                .firstName(firstName)
                .lastName(lastName)
                .telegramLink(telegramLink)
                .status(Status.valueOf("ACTIVE"))
                .role(Role.valueOf("USER"))
                .registrationDate(LocalDateTime.now())
                .build();
    }
}
