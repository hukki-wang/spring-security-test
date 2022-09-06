package com.hukki.example.service;

import com.hukki.example.dao.UserDao;
import com.hukki.example.dto.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SpringDataUserDetailsService implements UserDetailsService {

    @Autowired
    private UserDao userDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        /**
         * 如果重写了configure(AuthenticationManagerBuilder auth)则不生效
         */
        //登录账号
        System.out.println("username="+username);
        //根据账号去数据库查询...
        UserDto userDto = userDao.getUserByUsername(username);
        if (userDto == null){
            return null;
        }
        //查询用户权限
        List<String> permissions = userDao.findPermissionsByUserId(userDto.getId());
        String[] perarray = new String[permissions.size()];
        permissions.toArray(perarray);
        UserDetails userDetails = User.withUsername(userDto.getFullname()).password(userDto.getPassword()).authorities(perarray).build();
        return userDetails;
    }

    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("123"));
    }


}
