# @Bean注解

### 1、作用：

@Bean注解作用在方法上，用于告诉方法，产生一个Bean对象，该对象由Spring容器来管理。该对象只产生一次，下次直接复用该对象。

### 2、使用场景：

Bean注解的作用之一就是能够管理第三方jar包内的类到容器中。 现在我们引入一个第三方的jar包，这其中的某个类，StringUtil需要注入到我们的IndexService类中，
因为我们没有源码，不能再StringUtil中增加@Component或者@Service注解。这时候我们可以通过使用@Bean的方式，把这个类交到Spring容器进行管理，最终就能够被注入到IndexService实例中。
