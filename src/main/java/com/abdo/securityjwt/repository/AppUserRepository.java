package com.abdo.securityjwt.repository;

import com.abdo.securityjwt.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser,Long> {


        AppUser findByUsername(String name);


}
