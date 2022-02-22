package com.jwtauthentication.refreshtoken.dao;


import com.jwtauthentication.refreshtoken.entity.AdminRequest;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

@Repository
@Component
public interface AdminDao extends CrudRepository<AdminRequest,Long>{
    
    public AdminRequest getAdminRequestByid(int id);

    public AdminRequest getAdminRequestByemail(String email);

}