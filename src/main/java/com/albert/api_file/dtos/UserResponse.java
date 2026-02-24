package com.albert.api_file.dtos;

import com.albert.api_file.models.User;
import com.albert.api_file.utilites.DateFormatterUtility;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

@Getter
@Setter
public class UserResponse {

    private final UUID id;
    private String username;
    private String createdAt;

    public UserResponse(UUID id, String username, String createdAt) {
        this.id = id;
        this.username = username;
        this.createdAt = createdAt;
    }

    public static UserResponse fromModel(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getCreatedAt().format(DateFormatterUtility.DATE_TIME_FORMATTER)
        );
    }
}
