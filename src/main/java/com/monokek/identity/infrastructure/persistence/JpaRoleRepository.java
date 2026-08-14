package com.monokek.identity.infrastructure.persistence;

import com.monokek.identity.domain.Role;
import com.monokek.identity.domain.RoleRepository;
import org.springframework.data.jpa.repository.JpaRepository;

interface JpaRoleRepository extends RoleRepository, JpaRepository<Role, Long> {
}
