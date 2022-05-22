# Spring Security添加记住我功能

### 1.记住我功能原理

用户登录时，点击记住我选框，系统为用户生成一个cookie和session(这里是token)，cookie存在客户浏览器端，session(这里是token)存在服务器端，下次用户访问系统时，会将cookie携带上
，服务器端根据cookie查找session(这里是token)，查找成功后，直接访问资源，无需登录操作。

### 2.实现

1）修改配置文件，加入记住我的设置，需要配置token持久化仓库，因此需定义方法返回一个PersistentTokenRepository类供spring容器管理。
```java
package evooauth.evooauth.config;

import evooauth.evooauth.Filter.ValidateCodeFilter;
import evooauth.evooauth.Handler.MyAuthenticationFailureHandler;
import evooauth.evooauth.Handler.MyAuthenticationSucessHandler;
import evooauth.evooauth.Service.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * @Author 86180
 * @Date 2022/5/21 23:42
 * @Version 1.0
 * @Description
 **/
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;
    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private ValidateCodeFilter validateCodeFilter;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private MyUserDetailService myUserDetailService;

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        jdbcTokenRepository.setCreateTableOnStartup(false);//不自动生产数据库表，需要手动生成
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)// 添加验证码校验过滤器
                .formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                .loginPage("/authentication/require")// 登录跳转 URL
                .loginProcessingUrl("/login")// 处理表单登录 URL
                .successHandler(authenticationSucessHandler) // 处理登录成功
                .failureHandler(authenticationFailureHandler) // 处理登录失败
                .and()
                .rememberMe()
                .tokenRepository(persistentTokenRepository())// 配置 token 持久化仓库
                .tokenValiditySeconds(3600)// remember 过期时间，单为秒
                .userDetailsService(myUserDetailService)// 处理自动登录逻辑
                .and()
                .authorizeRequests() // 授权配置
                .antMatchers("/authentication/require",
                                         "/login.html",
                                         "/login/generateCode").permitAll()// 无需认证的请求路径
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                .and().csrf().disable();
    }
}

```
2）前端加入记住我功能
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>登录</title>
    <link rel="stylesheet" href="css/login.css" type="text/css">
</head>
<body>
<form class="login-page" action="/login" method="post">
    <div class="form">
        <h3>账户登录</h3>
        <input type="text" placeholder="用户名" name="username" required="required" />
        <input type="password" placeholder="密码" name="password" required="required" />
        <span style="display: inline">
            <input type="text" name="imageCode" placeholder="验证码" style="width: 50%;"/>
            <img src="/login/generateCode"/>
        </span>
        <input type="checkbox" name="remember-me"/> 记住我
        <button type="submit">登录</button>
    </div>
</form>
</body>
</html>

```

### 3.效果

![111](https://user-images.githubusercontent.com/62679490/169711370-07368474-7660-46c5-8688-399f5d98708e.png)

### 4.注意
【1】mysql版本要对应上；
【2】这里是自己手动生成的数据库表；
