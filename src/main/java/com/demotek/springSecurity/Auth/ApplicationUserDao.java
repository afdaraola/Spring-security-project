package com.demotek.springSecurity.Auth;

import java.util.Optional;

public interface ApplicationUserDao {
     Optional<ApplicationUser> selectApplicationUserByUserName(String userName);
}
