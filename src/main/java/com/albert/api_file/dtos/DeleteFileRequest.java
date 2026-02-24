package com.albert.api_file.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class DeleteFileRequest {
    private UUID id;
}
