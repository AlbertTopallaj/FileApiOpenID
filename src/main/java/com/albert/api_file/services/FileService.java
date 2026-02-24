package com.albert.api_file.services;

import com.albert.api_file.dtos.DeleteFileRequest;
import com.albert.api_file.exceptions.*;
import com.albert.api_file.models.File;
import com.albert.api_file.models.Folder;
import com.albert.api_file.models.User;
import com.albert.api_file.repositories.IFileRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FileService {

    private final IFileRepository fileRepository;

    /**
     * Saves a multipart file to the database with the including metadata.
     * The file content is stored in bytes with the information such as
     * owner, folder, size and even the time it was created
     *
     * @param file   the multipart file to be saved
     * @param owner  the user who owns this file
     * @param folder the folder where the file will be stored
     * @return the saved file
     * @throws FileIsEmptyException if the uploaded file is empty
     * @throws MissingFileNameException if the file is missing or blank
     * @throws FileAlreadyExistsException if the user already has a file with the same name
     */

    @Transactional
    public File saveFile(MultipartFile file, User owner, Folder folder) {

        if (file.isEmpty()) {
            throw new FileIsEmptyException();
        }

        if (file.getOriginalFilename() == null || file.getOriginalFilename().isBlank()){
            throw new MissingFileNameException();
        }

        if (fileRepository.existsByTitleAndOwner(file.getOriginalFilename(), owner)) {
            throw new FileAlreadyExistsException();
        }

        File fileToSave = new File();
        fileToSave.setFolder(folder);
        fileToSave.setTitle(file.getOriginalFilename());
        try {
            fileToSave.setContent(file.getBytes());
        } catch (IOException e) {
            throw new FileIsEmptyException();
        }

        fileToSave.setSize((int) file.getSize());
        fileToSave.setCreatedAt(LocalDateTime.now());
        fileToSave.setOwner(owner);

        return fileRepository.save(fileToSave);
    }

    /**
     * Get all files owned by a specific user
     *
     * @param user the user whose files should be from
     * @return a list of all files owned by a specified user
     */

    public List<File> getAllFiles(User user) {
        return fileRepository.findAllByOwner(user);
    }

    /**
     * Deletes a file from the database based on the given file ID
     *
     * @param request the delete request containing the file ID which is going to be deleted
     * @param user the owner of the file
     * @throws FileDoesntExistException if the file does not exist or does not belong to the user
     */

    @Transactional
    public void deleteFile(DeleteFileRequest request, User user) {

        File file = fileRepository.findByIdAndOwner(request.getId(), user)
                .orElseThrow(() -> new FileDoesntExistException());

        fileRepository.deleteById(file.getId());
    }

    /**
     * Gets a specific file based on its ID if the user is the owner
     *
     * @param id   the identifier of the file
     * @param user the user requesting access to the file
     * @return the file
     * @throws FileNotFoundException if the file is not found or the user is not the right owner
     */

    public File getFileById(UUID id, User user) {

        return fileRepository.findByIdAndOwner(id, user)
                .orElseThrow(() -> new FileNotFoundException());
    }
}
