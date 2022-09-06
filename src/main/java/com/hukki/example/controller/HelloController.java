package com.hukki.example.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @RequestMapping("/hello")
    public String hello(){
        System.out.println("hello security!");
        return "hello security!";
    }

    @RequestMapping(value = "/login-success")
    public String loginSuc(){
        System.out.println("hello security!");
        String username = getUsername();
        return username+"登录成功!";
    }

    @RequestMapping("/login-fail")
    public String loginFail(){
        System.out.println("hello security!");
        return "登录失败!";
    }

    private String getUsername(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!authentication.isAuthenticated()){
            return null;
        }
        Object principal = authentication.getPrincipal();
        String username = null;
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            username =
                    ((org.springframework.security.core.userdetails.UserDetails)principal).getUsername();
        } else {
            username = principal.toString();
        }
        return username;
    }

    @RequestMapping("/test")
    public String test(){
        System.out.println("hello security!");
        return "test无需认证!";
    }

    @RequestMapping("/p/p1")
    public String auth(){
        System.out.println("hello security!");
        return "test权限认证!";
    }

    @RequestMapping("/r/r1")
    public String role(){
        System.out.println("hello security!");
        return "test角色认证!";
    }
}

