package com.demotek.springSecurity.Auth;

import com.demotek.springSecurity.SecurityConfig.ApplicationUserRoles;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;


import java.util.List;
import java.util.Optional;

import static com.demotek.springSecurity.SecurityConfig.ApplicationUserRoles.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {


    private PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String userName) {
        return getApplicationUser()
                .stream()
                .filter(applicationUser -> userName.equals(applicationUser.getUsername()))
                .findFirst();
    }


    private List<ApplicationUser> getApplicationUser() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(passwordEncoder.encode("password"), "festus", USER.getGrantedAuthorities(),
                        true, true, true, true),
                new ApplicationUser(passwordEncoder.encode("password"), "alvin", ADMIN.getGrantedAuthorities(),
                        true, true, true, true),
                new ApplicationUser(passwordEncoder.encode("password"), "tom", ADMINTRAINEE.getGrantedAuthorities(),
                        true, true, true, true)
        );

        return applicationUsers;
    }
}
