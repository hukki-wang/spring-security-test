package com.hukki.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//AOP :拦截器
//@EnableWebSecurity(由于Spring boot starter自动装配机制，这里无需使用@EnableWebMvc与@ComponentScan)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //链式编程
    //授权登录认证+资源授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问  功能页面只有有对应权限的人才可以访问
        //请求授权的规则
        //登录  可以配置一些属性
        http
                //认证成功跳转页面,失败跳转失败页面
                .formLogin().successForwardUrl("/login-success")
//                .failureForwardUrl("/login-fail")
                //注销报错，关闭防网站攻击
                .and()
                .csrf().disable()
                //开启记住我功能 一次登录，后面在有效期内免登录
//                .rememberMe()
//                .and()
                //认证配置 可以配置一些无需认证的路径和指定权限的路径，后续配置
                .authorizeRequests()
                //匹配到的请求需要认证
                .antMatchers("/level1/**").authenticated()
                //匹配到的请求通过认证
                .antMatchers("/test/**").permitAll()
                //访问/r/r1资源的 url需要拥有p1权限
                .antMatchers("/p/p1**").hasAuthority("p1")
                .antMatchers("/p/p2").hasAuthority("p2")
                //指定了"/p/p3"URL，同时拥有p1和p2权限才能够访问
                .antMatchers("/p/p3").access("hasAuthority('p1') and hasAuthority('p2')")
                //访问/r/r1资源的 url需要拥有r1角色(用户登录后具有vip3角色后可以访问该资源，如果直接访问会跳转到登录页面)
                .antMatchers("/r/r1/**").hasRole("vip3")
                //任何请求都需要认证
                .anyRequest().authenticated();

    }

    /**
     * 密码加密方式
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //角色和用户资源授权(该处可以添加管理员角色，真正的角色和用户以及权限可以抽象到UserDetailService中处理，采用数据库持久化)
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("cjp").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
//                .and()
//                .withUser("cs").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
//                .and()
//                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
//    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("zhangsan").password("123").authorities("p1").build());
//        manager.createUser(User.withUsername("lisi").password("456").authorities("p2").build());
//        return manager;
//    }
}
