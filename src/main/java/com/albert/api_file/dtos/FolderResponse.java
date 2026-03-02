package com.albert.api_file.dtos;

import com.albert.api_file.controllers.FolderController;
import com.albert.api_file.models.File;
import com.albert.api_file.models.Folder;
import com.albert.api_file.models.User;
import com.albert.api_file.utilites.DateFormatterUtility;
import lombok.Getter;
import lombok.Setter;
import org.springframework.hateoas.RepresentationModel;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@Getter
@Setter
public class FolderResponse extends RepresentationModel<FolderResponse> {

    private final UUID id;
    private String name;
    private List<FileResponse> files;
    private String owner;

    public FolderResponse(UUID id, String name, List<FileResponse> files, String owner) {
        this.id = id;
        this.name = name;
        this.files = files;
        this.owner = owner;
    }

    public static FolderResponse fromModel(Folder folder) {

        List<FileResponse> fileResponses = folder.getFiles().stream()
                .map(FileResponse::fromModel)
                .toList();

        FolderResponse response = new FolderResponse(
                folder.getId(),
                folder.getName(),
                fileResponses,
                folder.getOwner().getUsername()
        );

        response.add(linkTo(methodOn(FolderController.class).getFolderById(folder.getId(), null))
                .withSelfRel());

        return response;
    }
}
