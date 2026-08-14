package com.monokek.identity.infrastructure.persistence;

import com.monokek.identity.domain.User;
import com.monokek.identity.domain.UserRepository;
import org.springframework.data.jpa.repository.JpaRepository;

interface JpaUserRepository extends UserRepository, JpaRepository<User, Long> {
}
