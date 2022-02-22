package com.jwtauthentication.refreshtoken.service;

import com.jwtauthentication.refreshtoken.config.MySecurityConfig;
import com.jwtauthentication.refreshtoken.dao.UserDao;
import com.jwtauthentication.refreshtoken.entity.AuthenticationResponse;
import com.jwtauthentication.refreshtoken.entity.UserRequest;
import com.jwtauthentication.refreshtoken.helper.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class JwtService {
    
    @Autowired
    public UserRequest userRequest;

    @Autowired
    public UserDao userDao;

    @Autowired
    public AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationResponse authenticationResponse;

    @Autowired
    public CustomUserDetailsService customUserDetailsService;

    @Autowired
    public JwtUtil jwtUtil;

    @Autowired
    public MySecurityConfig mySecurityConfig;

    public ResponseEntity<?> addUser(String email,String password){
        try {
        
            
            String encodedPassword = mySecurityConfig.passwordEncoder().encode(password);

            userRequest.setUseremail(email);
            userRequest.setPassword(encodedPassword);
            userDao.save(userRequest);

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password)); //spring security
        
        } catch (Exception e) {
            e.printStackTrace();
            authenticationResponse.setMessage(e.getMessage());
            authenticationResponse.setToken(null);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(authenticationResponse);
        }
        
        //admin has been authenticated successfully
            
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(email); //username == email
            
        String token = jwtUtil.generateToken(userDetails);

        authenticationResponse.setMessage("Admin Registered successfully");
        authenticationResponse.setToken(token);
        return ResponseEntity.ok(authenticationResponse);
    }
}
