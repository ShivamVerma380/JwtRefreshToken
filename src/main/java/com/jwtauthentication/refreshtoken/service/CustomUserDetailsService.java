package com.jwtauthentication.refreshtoken.service;

import java.util.ArrayList;

import com.jwtauthentication.refreshtoken.dao.AdminDao;
import com.jwtauthentication.refreshtoken.dao.UserDao;
import com.jwtauthentication.refreshtoken.entity.AdminRequest;
import com.jwtauthentication.refreshtoken.entity.UserRequest;
import com.jwtauthentication.refreshtoken.helper.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailsService implements UserDetailsService  {

    @Autowired
    public UserRequest userRequest;

    @Autowired
    public UserDao userDao;

    @Autowired
    public AdminRequest adminRequest;

    @Autowired
    public AdminDao adminDao;

    @Autowired
    public JwtUtil jwtUtil;

    public UserRequest findByUserName(String email){
        userRequest = userDao.getUserRequestByuseremail(email);
        return userRequest;
    }

    public AdminRequest findByAdminName(String email){
        adminRequest = adminDao.getAdminRequestByemail(email);
        return adminRequest;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        userRequest = findByUserName(username);
        if(userRequest!=null){
            return new User(userRequest.getUseremail(),userRequest.getPassword(),new ArrayList<>());
        }

        adminRequest = findByAdminName(username);
        if(adminRequest!=null){
            return new User(adminRequest.getEmail(),adminRequest.getPassword(),new ArrayList<>());
        }


        throw new UsernameNotFoundException("User not found");
        
    }
    
}
