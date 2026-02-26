package com.albert.api_file.repositories;

import com.albert.api_file.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface IUserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByUsername(String username);
    Optional<User> findByOidcAndOidcProvider(String oidcId, String oidcProvider);

    boolean existsByUsername(String username);
}
