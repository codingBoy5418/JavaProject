
# Spring Boot中开启Spring Security

### 1.使用

1）SpringBoot项目中引入SpringSecurity

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

2）定义一个Controller类，启动项目并访问，跳转到SpringSecurity自带的登录页面
![image](https://user-images.githubusercontent.com/62679490/169701336-91f3f72f-ef41-4d0f-bd23-f60451593351.png)

### 2.基本原理
![image](https://user-images.githubusercontent.com/62679490/169701725-35c02496-cffd-4b24-a08e-92ffd882b4df.png)

SpringSecurity中包含多个过滤器，这些过滤器形成一条过滤器链，所有请求必须通过过滤器链才能成功访问资源。具体如下：

- UsernamePasswordAuthenticationFilter过滤器用于处理基于表单方式的登录认证；
- BasicAuthenticationFilter用于处理基于HTTP Basic方式的登录验证；
- 后面还可能包含一系列别的过滤器（可以通过相应配置开启）；
- 在过滤器链末尾是一个名为FilterSecurityInterceptor的拦截器，用于判断当前请求身份认证是否成功，是否有相应的权限，当身份认证失败或者权限不足的时候便会抛出相应的异常。 
- ExceptionTranslateFilter捕获并处理，所以我们在ExceptionTranslateFilter过滤器用于处理了FilterSecurityInterceptor抛出的异常并进行处理，比如需要身份认证时将请求重定向到相应的认证页面，当认证失败或者权限不足时返回相应的提示信息。

流程如下：
- 用户请求/test请求资源；
- 请求到达FilterSecurityInterceptor拦截器，发现用户未登录，抛异常；
- 异常被ExceptionTranslateFilter捕获并处理，跳转到登录页面；
- 用户输入用户名和密码登录，被UsernamePasswordAuthenticationFilter过滤器处理；
- 处理通过后，FilterSecurityInterceptor拦截器检查权限，通过后进入Controller层，访问资源。
