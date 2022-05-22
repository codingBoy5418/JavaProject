
# Spring Security添加图形验证码

### 1.后端生成验证码
在Controller中定义生成验证码的接口，定义验证码对象，包含验证码图片、过期时间、验证码数值
```java
@GetMapping("/generateCode")
    public void generateCode(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ImageCode imageCode = loginService.generateCode();//定义验证码对象，包含验证码图片、过期时间(60s)、验证码数值
        sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY_IMAGE_CPDE, imageCode);//session中添加验证码
        ImageIO.write(imageCode.getBufferedImage(), "jpeg", response.getOutputStream());
    }
```
### 2.前端显示验证码
前端直接用</img src="后端图片位置">来显示验证码
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
        <button type="submit">登录</button>
    </div>
</form>
</body>
</html>

```
### 3.后端添加验证码校验逻辑【过滤器中添加校验逻辑】
验证码在用户名和密码之前校验，因此需定义过滤器ValidateCodeFilter，在该过滤器中进行验证码的校验逻辑。
```java
package evooauth.evooauth.Filter;

import evooauth.evooauth.Controller.LoginController;
import evooauth.evooauth.Exception.ValidateCodeException;
import evooauth.evooauth.PO.ImageCode;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.social.connect.web.HttpSessionSessionStrategy;
import org.springframework.social.connect.web.SessionStrategy;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author 86180
 * @Date 2022/5/23 0:31
 * @Version 1.0
 * @Description
 **/
 
@Component
public class ValidateCodeFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(StringUtils.equalsIgnoreCase("/login", request.getRequestURI()) && StringUtils.equalsIgnoreCase(request.getMethod(), "post")){
            try{
                validateCode(new ServletWebRequest(request));
            }catch (ValidateCodeException e){
                authenticationFailureHandler.onAuthenticationFailure(request, response, e);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void validateCode(ServletWebRequest servletWebRequest) throws ServletRequestBindingException, ValidateCodeException {
        ImageCode codeInSession = (ImageCode) sessionStrategy.getAttribute(servletWebRequest, LoginController.SESSION_KEY_IMAGE_CPDE);
        String codeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "imageCode");

        if (StringUtils.isBlank(codeInRequest)) {
            throw new ValidateCodeException("验证码不能为空！");
        }
        if (codeInSession == null) {
            throw new ValidateCodeException("验证码不存在！");
        }
        if (codeInSession.isExpire()) {
            sessionStrategy.removeAttribute(servletWebRequest, LoginController.SESSION_KEY_IMAGE_CPDE);
            throw new ValidateCodeException("验证码已过期！");
        }
        if (!StringUtils.equalsIgnoreCase(codeInSession.getCode(), codeInRequest)) {
            throw new ValidateCodeException("验证码不正确！");
        }
        sessionStrategy.removeAttribute(servletWebRequest, LoginController.SESSION_KEY_IMAGE_CPDE);

    }
}
```
### 4.校验失败时，抛异常，这里定义一个验证码校验异常，继承AuthenticationException
```java
package evooauth.evooauth.Exception;
import org.springframework.security.core.AuthenticationException;

/**
 * @Author 86180
 * @Date 2022/5/23 0:29
 * @Version 1.0
 * @Description
 **/

public class ValidateCodeException extends AuthenticationException {
    public ValidateCodeException(String message) {
        super(message);
    }
}
```
### 5.当出现异常时，controller类捕获异常，执行验证码校验失败类的逻辑。
```java
package evooauth.evooauth.Handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author 86180
 * @Date 2022/5/22 1:24
 * @Version 1.0
 * @Description
 **/
@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private ObjectMapper mapper;


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(mapper.writeValueAsString(exception.getMessage()));
    }
}

```

### 6.过滤器ValidateCodeFilter应该在UsernamePasswordAuthenticationFilter过滤器之前过滤，需要在配置类中进行配置。
```java
package evooauth.evooauth.config;

import evooauth.evooauth.Filter.ValidateCodeFilter;
import evooauth.evooauth.Handler.MyAuthenticationFailureHandler;
import evooauth.evooauth.Handler.MyAuthenticationSucessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
![111](https://user-images.githubusercontent.com/62679490/169708675-350a3588-c6f1-4dd1-804c-00d0696686ba.png)

