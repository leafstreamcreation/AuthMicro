package com.example.authmicro.repository;

import com.example.authmicro.entity.AuthUser;
import com.example.authmicro.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthUserRepository extends JpaRepository<AuthUser, Long> {
    
    Optional<AuthUser> findByEmail(String email);
    
    boolean existsByEmail(String email);
    
    List<AuthUser> findByRole(Role role);
    
    List<AuthUser> findByEnabledTrue();
    
    long countByRole(Role role);
}
