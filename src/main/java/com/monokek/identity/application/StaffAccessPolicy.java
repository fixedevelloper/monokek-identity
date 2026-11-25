package com.monokek.identity.application;

import com.monokek.identity.common.ApiException;
import com.monokek.identity.domain.User;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

/**
 * Who may act on which staff account. The path/method annotations only say "admin or manager"; this is the
 * rule that keeps a manager inside their own branch and below the admin role:
 * <ul>
 *   <li>an admin may do anything;</li>
 *   <li>any other requester must belong to a branch, and only manages non-admin staff of that same branch;</li>
 *   <li>nobody changes their own permissions, and a non-admin only grants permissions they hold themselves.</li>
 * </ul>
 */
@Component
public class StaffAccessPolicy {

    private static final Set<String> PRIVILEGED_ROLES = Set.of("admin", "super-admin");

    public boolean isAdmin(User user) {
        return user.getRoles().stream().anyMatch(r -> "admin".equalsIgnoreCase(r.getName()));
    }

    public boolean isPrivilegedRole(String roleName) {
        return roleName != null && PRIVILEGED_ROLES.contains(roleName.toLowerCase());
    }

    /** Branch a non-admin requester is confined to; an admin has none. */
    public Long confinedBranch(User requester) {
        if (isAdmin(requester)) {
            return null;
        }
        if (requester.getBranchId() == null) {
            throw ApiException.forbidden("Votre compte n'est rattaché à aucune succursale.");
        }
        return requester.getBranchId();
    }

    /** May {@code requester} create an account with this role in this branch? Returns the branch to store. */
    public Long checkCreate(User requester, String role, Long branchId) {
        if (isAdmin(requester)) {
            return branchId;
        }
        Long own = confinedBranch(requester);
        if (isPrivilegedRole(role)) {
            throw ApiException.forbidden("Seul un administrateur peut créer un compte administrateur.");
        }
        if (branchId != null && !branchId.equals(own)) {
            throw ApiException.forbidden("Vous ne pouvez gérer que le personnel de votre succursale.");
        }
        return own;
    }

    /** May {@code requester} act on {@code target} (edit, delete, set a PIN)? */
    public void checkManage(User requester, User target) {
        if (isAdmin(requester)) {
            return;
        }
        Long own = confinedBranch(requester);
        boolean targetPrivileged = target.getRoles().stream().anyMatch(r -> isPrivilegedRole(r.getName()));
        if (targetPrivileged) {
            throw ApiException.forbidden("Seul un administrateur peut agir sur un compte administrateur.");
        }
        if (!Objects.equals(own, target.getBranchId())) {
            throw ApiException.forbidden("Ce membre du personnel appartient à une autre succursale.");
        }
    }

    /** A non-admin keeps staff in their own branch: no moving someone elsewhere, no detaching them from a branch. */
    public void checkBranchChange(User requester, Long newBranchId, boolean clearBranch) {
        if (isAdmin(requester)) {
            return;
        }
        Long own = confinedBranch(requester);
        if (clearBranch || (newBranchId != null && !newBranchId.equals(own))) {
            throw ApiException.forbidden("Vous ne pouvez pas changer la succursale d'un membre du personnel.");
        }
    }

    /** May {@code requester} replace {@code target}'s direct permissions with {@code requested}? */
    public void checkGrant(User requester, User target, Collection<String> requested) {
        if (isAdmin(requester)) {
            return;
        }
        if (requester.getId().equals(target.getId())) {
            throw ApiException.forbidden("Vous ne pouvez pas modifier vos propres permissions.");
        }
        checkManage(requester, target);
        Set<String> held = requester.getAllPermissionNames();
        for (String name : requested) {
            if (!held.contains(name)) {
                throw ApiException.forbidden("Vous ne pouvez pas accorder une permission que vous n'avez pas : " + name);
            }
        }
    }
}
