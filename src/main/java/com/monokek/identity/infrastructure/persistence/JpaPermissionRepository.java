package com.monokek.identity.infrastructure.persistence;

import com.monokek.identity.domain.Permission;
import com.monokek.identity.domain.PermissionRepository;
import org.springframework.data.jpa.repository.JpaRepository;

interface JpaPermissionRepository extends PermissionRepository, JpaRepository<Permission, Long> {
}
