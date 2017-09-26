# Jackson Field Security

Provides a simple way to add field level security to your Spring Boot applications with the help of Jackson filters.

## Prerequisites

This library depends on [Jackson](https://github.com/FasterXML/jackson). It does not require [Spring Security](https://github.com/spring-projects/spring-security) or [Spring Data](https://github.com/spring-projects/spring-data-commons) but it will provide auto-configurations for them if they are available.  

## Getting Started

Add the library to your application with Maven or Gradle.

Maven:
```xml
<dependency>
    <groupId>com.jahnelgroup.jackson</groupId>
    <artifactId>jackson-field-security</artifactId>
    <version>1.0.3</version>
</dependency>
```

Gradle:

```
compile('com.jahnelgroup.jackson:jackson-field-security:1.0.3')
```

## How it works

This library registers a Jackson filter to conditionally control access to fields based on policies. The filter will detect the current logged in user and the owner of the data being serialized together with the policies to determine access. 

Here are the main interfaces that drive this flow:

* **PrincipalProvider** interface will identify the current logged in user (a.ka., the Principal). The default auto-configuration will use Spring Security's SecurityContextHolder. To provide your own custom implementation register a bean of type PrincipalProvider. 
* **EntityCreatedByProvider** interface will identify the owner of the serialized object. The default auto-configuration will use the field annotated by Spring Data's **@CreatedBy**. To provide your own custom implementation register a bean of type EntityCreatedByProvider.
* **FieldSecurityPolicy** and **ContextAwareFieldSecurityPolicy** interfaces define policies for permitting a field.  
* **AccessDeniedExceptionHandler** interface will determine if any exception thrown by a policy should permit/deny a field. The default auto-configuration will attempt to use Spring Security's AccessDeniedException as an indicator that the field should be denied, otherwise the exception is rethrown to the framework. To provide your own custom implementation register a bean of type AccessDeniedExceptionHandler.

## Usage

Annotate your class with **@JsonFilter("securityFilter")** and the fields that need to be protected with **@SecureField**. Any entity with a field annotated by @SecureField must have the class annotated with @JsonFilter otherwise the security filter will not be invoked.

```java
@JsonFilter("securityFilter")
@Entity
class User {
    
    @Id @GeneratedValue
    Long id;
    
    // list of groups that this user belongs to 
    List<Long> groupIds = new ArrayList<Long>();
    
    // possibly populated by Spring Data's AuditingEntityListener
    @CreatedBy
    String username;
    
    String firstName;
    String lastName;

    // By default this will use the CreatedByFieldSecurityPolicy
    // which compares the logged in user against the @CreatedBy field
    // resulting in having this field only to be seen by the user who 
    // created the entity. 
    @SecureField        
    String mySecret;
    
    // You can specify a list of custom policies. Here we are 
    // protecting a field that can be seen by anyone in the same group
    // or they have the ADMIN role. 
    @SecureField( policyClasses = {GroupPolicy.class},
        roles = arrayOf("ADMIN"), policyLogic = EvalulationLogic.OR )     
    String groupSecret;    
    
}
```

Here is a possible custom GroupPolicy implementation:

```java
class GroupPolicy implements ContextAwareFieldSecurityPolicy {

    private ApplicationContext appContext;

    // return true to permit the field, false to deny it
    public boolean permitAccess(PropertyWriter writer, Object target, 
        String targetCreatedByUser, String currentPrincipalUser) {
        
        return target instanceof User && 
            ((User)target).getGroupIds().stream()
                .anyMatch(getPrincipalGroupIds(currentPrincipalUser));
       
    }
         
    // here you can get a handle to your spring beans
    public void setApplicationContext(ApplicationContext appContext){
        this.appContext = appContext;   
    }
    
    private List<Long> getPrincipalGroupIds(String currentPrincipalUser){
        UserService userService = (UserService) applicationContext.getBean("userService");
        return userService.findByUsername(currentPrincipalUser).getGroupIds();
    }

}
```

## Policy Classes v.s. Policy Beans

You have the option to declare policies as either regular Objects (policyClasses) or Spring managed Bean's (policyBeans). The GroupPolicy example above demonstrates an unmanaged policy, the library would create a brand new instance of this policy each time. If you want to take advantage of being a Spring managed Bean then declare your policy as such and reference it via the Bean name with policyBeans. 
 
### Spring Security ACL

Writing a policy as a Spring managed bean can be an effective way to adapt into Spring Security's ACL with SpEL. Here is an example of writing a policy to permit a field if the Principal has the ADMIN role. 

```java
@Component("adminFieldPolicy")
class AdminFieldPolicy implements FieldSecurityPolicy {

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public boolean permitAccess(PropertyWriter writer, Object target, 
        String targetCreatedByUser, String currentPrincipalUser) {
        return true;
    }

}
```

You would need to use the **@EnableGlobalMethodSecurity(prePostEnabled = true)** annotation to enable Spring's method level security.

```java
@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
class App{
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
``` 

Then annotate your field:

```java
@SecureField( policyBeans = {"adminFieldPolicy"} ) 
String adminSecret;
```
 
## Debugging

You can increase the logging level to inspect how the security policies are being processed.

Edit you **application.properties** with:
```
logging.level.com.jahnelgroup.jackson.security=DEBUG
```
