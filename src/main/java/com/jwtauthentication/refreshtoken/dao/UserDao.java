package com.jwtauthentication.refreshtoken.dao;


import com.jwtauthentication.refreshtoken.entity.UserRequest;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

@Repository
@Component
public interface UserDao extends CrudRepository<UserRequest,Long>{

    //public  UserRequest getJwtRequestById(int id);

    //public UserRequest getJwtRequestByuseremail(String useremail);

    public UserRequest getUserRequestById(int id);

    public UserRequest getUserRequestByuseremail(String god);
    //always name methods with get_Entityname_By_variable_name;

}