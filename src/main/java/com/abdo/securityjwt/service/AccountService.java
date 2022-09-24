package com.abdo.securityjwt.service;

import com.abdo.securityjwt.entity.AppRole;
import com.abdo.securityjwt.entity.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
