package com.albert.api_file.dtos;

import com.albert.api_file.controllers.UserController;
import com.albert.api_file.models.User;
import com.albert.api_file.utilites.DateFormatterUtility;
import lombok.Getter;
import lombok.Setter;
import org.springframework.hateoas.RepresentationModel;

import java.util.Date;
import java.util.UUID;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@Getter
@Setter
public class UserResponse extends RepresentationModel<UserResponse> {

    private final UUID id;
    private String username;
    private String createdAt;

    public UserResponse(UUID id, String username, String createdAt) {
        this.id = id;
        this.username = username;
        this.createdAt = createdAt;
    }

    public static UserResponse fromModel(User user) {
        UserResponse response = new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getCreatedAt().format(DateFormatterUtility.DATE_TIME_FORMATTER)
        );

        response.add(linkTo(methodOn(UserController.class).getUserById(user.getId()))
                .withSelfRel());

        return response;
    }
}
