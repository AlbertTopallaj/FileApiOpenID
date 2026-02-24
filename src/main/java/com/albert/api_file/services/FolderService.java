package com.albert.api_file.services;

import com.albert.api_file.dtos.CreateFolderRequest;
import com.albert.api_file.dtos.DeleteFolderRequest;
import com.albert.api_file.exceptions.FolderDoesntExistException;
import com.albert.api_file.exceptions.FolderNotFoundException;
import com.albert.api_file.exceptions.MissingFolderNameException;
import com.albert.api_file.models.Folder;
import com.albert.api_file.models.User;
import com.albert.api_file.repositories.IFileRepository;
import com.albert.api_file.repositories.IFolderRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class FolderService {

    private final IFolderRepository folderRepository;
    private final IFileRepository fileRepository;

    /**
     * @param request the create request containing the folders name given by the user
     * @param user    the user who creates the file and owns it
     * @return folder the folder that was just created with the name and a ID
     * @throws MissingFolderNameException if the folder name is null or blank
     */


    public Folder createFolder(CreateFolderRequest request, User user) {
        if (request.getName() == null || request.getName().isBlank()) {
            throw new MissingFolderNameException();
        }


        var folder = new Folder(request.getName(), user);
        log.info("Folder saved: {}", request.getName());
        folder.setOwner(user);

        folder = folderRepository.save(folder);
        return folder;
    }

    /**
     * Get all folders owned by a specific user
     *
     * @param user the user who owns the folders
     * @return a list of all the folders and their information and also the files in those folders
     * only the folders that the user owns
     */

    public List<Folder> getAllFolders(User user) {
        return folderRepository.findAllByOwner(user);
    }

    /**
     * Deletes a folder from the database based on the given folder ID
     *
     * @param request the delete request containing the folders ID
     * @param user the owner of the folder
     * @throws FolderDoesntExistException if the folder does not exist or does not belong to the user
     */

    @Transactional
    public void deleteFolder(DeleteFolderRequest request, User user) {
        Folder folder = folderRepository.findByIdAndOwner(request.getId(), user)
                .orElseThrow(() -> new FolderDoesntExistException());


        fileRepository.deleteAllByFolder(folder);

        folderRepository.delete(folder);
    }

    /**
     * Get a specific folder based on its ID if the user is the owner
     *
     * @param id   the identifier of the folder
     * @param user the user requesting access to the folder
     * @return the folder if found and owned by the user
     * @throws FolderNotFoundException if the folder does not exist or does not belong to the user
     */

    public Folder getFolderById(UUID id, User user) {
        return folderRepository.findByIdAndOwner(id, user)
                .orElseThrow(() -> new FolderNotFoundException());
    }
}
