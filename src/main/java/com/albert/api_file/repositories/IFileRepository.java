package com.albert.api_file.repositories;

import com.albert.api_file.models.File;
import com.albert.api_file.models.Folder;
import com.albert.api_file.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IFileRepository extends JpaRepository<File, UUID> {
    List<File> findAllByOwner(User owner);

    Optional<File> findByIdAndOwner(UUID id, User owner);

    void deleteAllByFolder(Folder folder);

    boolean existsByTitleAndOwner(String title, User owner);
}
