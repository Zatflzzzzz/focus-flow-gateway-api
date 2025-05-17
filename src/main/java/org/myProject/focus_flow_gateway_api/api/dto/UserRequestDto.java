package org.myProject.focus_flow_gateway_api.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Role;
import org.myProject.focus_flow_gateway_api.api.dto.enums.Status;

import java.time.LocalDateTime;

@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
public class UserRequestDto {

    @NonNull
    String email;

    @NonNull
    String password;

    @NonNull
    String username;

    @NonNull
    String firstName;

    @NonNull
    String lastName;

    @NonNull
    @JsonProperty("telegram_link")
    String telegramLink;

    Status status;

    Role role;

    @Builder.Default
    @JsonProperty("registration_date")
    LocalDateTime registrationDate = LocalDateTime.now();
}
