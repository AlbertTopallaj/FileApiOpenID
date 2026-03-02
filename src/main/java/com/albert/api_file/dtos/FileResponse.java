package com.albert.api_file.dtos;

import com.albert.api_file.controllers.FileController;
import com.albert.api_file.models.File;
import com.albert.api_file.models.Folder;
import com.albert.api_file.models.User;
import com.albert.api_file.utilites.DateFormatterUtility;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.hateoas.RepresentationModel;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.UUID;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@Getter
@AllArgsConstructor
public class FileResponse extends RepresentationModel<FileResponse> {

    private final UUID id;
    private String title;
    private byte[] content;

    private String owner;

    private UUID folderId;
    private String createdAt;

    public static FileResponse fromModel(File file) {
       FileResponse response = new FileResponse(
                file.getId(),
                file.getTitle(),
                file.getContent(),
                file.getOwner().getUsername(),
                file.getFolder() != null ? file.getFolder().getId() : null,
                file.getCreatedAt().format(DateFormatterUtility.DATE_TIME_FORMATTER)
        );

       response.add(linkTo(methodOn(FileController.class).getFileById(file.getId(), null))
               .withSelfRel());

       response.add(linkTo(methodOn(FileController.class).downloadFile(file.getId(), null))
               .withRel("download"));

       return response;
    }
}
