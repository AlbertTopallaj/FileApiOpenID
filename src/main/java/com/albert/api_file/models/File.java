package com.albert.api_file.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Entity(name = "files")
@Getter
@Setter
@NoArgsConstructor
public class File {

    @Id
    private UUID id = UUID.randomUUID();

    @Column(nullable = false)
    private String title;

    @Lob
    @Column(nullable = false)
    private byte[] content;

    @Column(nullable = false)
    private int size;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @ManyToOne(fetch = FetchType.LAZY)
    private Folder folder;

    @Column(nullable = false)
    private LocalDateTime createdAt;

}
