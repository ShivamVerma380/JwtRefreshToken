package com.jwtauthentication.refreshtoken.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.jwtauthentication.refreshtoken.helper.JwtUtil;
import com.jwtauthentication.refreshtoken.service.CustomUserDetailsService;

import org.apache.coyote.RequestInfo;
import org.hibernate.engine.internal.Nullability.NullabilityCheckType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;


@Component
public class CustomJwtAuthenticationFilter extends OncePerRequestFilter{

    @Autowired
    public JwtUtil jwtUtil;

    @Autowired
    public CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // TODO Auto-generated method stub
        try {
            String jwtToken = extractJwtFromRequest(request);
            if(StringUtils.hasText(jwtToken) && jwtUtil.validateToken(jwtToken)){
                //UserDetails userDetails = new User(jwtUtil.extractUserName(jwtToken),"",jwtUtil.g);
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(jwtUtil.extractUserName(jwtToken));
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                // After setting the Authentication in the context, we specify
				// that the current user is authenticated. So it passes the
				// Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            }else{
                System.out.println("Cannot set the security context");
            }
        } catch (ExpiredJwtException e) {
            String isRefreshToken = request.getHeader("isRefreshToken");
            String requestUrl = request.getRequestURL().toString();
            // allow for Refresh Token creation if following conditions are true.
            if(isRefreshToken.equalsIgnoreCase("true") && requestUrl.contains("refresh-token")){
                allowForRefreshToken(e,request);
            }
        }catch(BadCredentialsException b){
            request.setAttribute("Bad Credentials",b );

        }catch(Exception e){
            e.printStackTrace();
        }
        filterChain.doFilter(request, response);
    }

    private void allowForRefreshToken(ExpiredJwtException e, HttpServletRequest request) {
        // create a UsernamePasswordAuthenticationToken with null values.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(null,null,null);
        // After setting the Authentication in the context, we specify
		// that the current user is authenticated. So it passes the
		// Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        // Set the claims so that in controller we will be using it to create
		// new JWT
        request.setAttribute("claims", e.getClaims());

    }


    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")){
            return bearerToken.substring(7);
        }
        return null;
    }
    
}
