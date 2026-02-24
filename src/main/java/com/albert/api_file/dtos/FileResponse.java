package com.albert.api_file.dtos;

import com.albert.api_file.models.File;
import com.albert.api_file.models.Folder;
import com.albert.api_file.models.User;
import com.albert.api_file.utilites.DateFormatterUtility;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.UUID;

@Getter
@AllArgsConstructor
public class FileResponse {

    private final UUID id;
    private String title;
    private byte[] content;

    private String owner;

    private UUID folderId;
    private String createdAt;

    public static FileResponse fromModel(File file) {
        return new FileResponse(
                file.getId(),
                file.getTitle(),
                file.getContent(),
                file.getOwner().getUsername(),
                file.getFolder() != null ? file.getFolder().getId() : null,
                file.getCreatedAt().format(DateFormatterUtility.DATE_TIME_FORMATTER)
        );
    }
}
