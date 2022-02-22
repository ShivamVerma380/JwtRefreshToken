package com.jwtauthentication.refreshtoken.controller;

import java.net.PortUnreachableException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import com.jwtauthentication.refreshtoken.entity.AuthenticationResponse;
import com.jwtauthentication.refreshtoken.helper.JwtUtil;
import com.jwtauthentication.refreshtoken.service.JwtService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.impl.DefaultClaims;

@RestController
public class JwtController {
    
    @Autowired
    public JwtService jwtService;

    @Autowired
    public JwtUtil jwtUtil;

    @Autowired
    public AuthenticationResponse authenticationResponse;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestParam("email") String email,@RequestParam("password") String password){
        return jwtService.addUser(email, password);

    }

    @GetMapping("/welcome")
    public ResponseEntity<?> getString(){
        return ResponseEntity.ok("Welcome!!");
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) throws Exception{
        // From the HttpRequest get the claims
        DefaultClaims claims = (io.jsonwebtoken.impl.DefaultClaims) request.getAttribute("claims");

        Map<String,Object> expectedMap = getMapFromIoJsonwebtokenClaims(claims);

        String token = jwtUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());

        authenticationResponse.setMessage("Token refreshed successfully!!");
        authenticationResponse.setToken(token);
        return ResponseEntity.ok(authenticationResponse);

    }

    private Map<String, Object> getMapFromIoJsonwebtokenClaims(DefaultClaims claims) {
        Map<String, Object> expectedMap = new HashMap<String, Object>();
		for (Entry<String, Object> entry : claims.entrySet()) {
			expectedMap.put(entry.getKey(), entry.getValue());
		}
		return expectedMap;
    }
}
