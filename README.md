# Jackson Field Security

Provides a simple way to add field level security to your Spring Boot applications with the help of Jackson filters.

## Prerequisites

This library depends on Jackson, it does not require Spring Security or Spring Data but will provide auto-configurations for them if they are available.  

## Getting Started

Add the library to your application with Maven or Gradle.

Maven:
```xml
<dependency>
    <groupId>com.jahnelgroup.jackson</groupId>
    <artifactId>jackson-field-security</artifactId>
    <version>1.0.2</version>
</dependency>
```

Gradle:

```
compile('com.jahnelgroup.jackson:jackson-field-security:1.0.2')
```

## How it works

This library registers a [Jackson](https://github.com/FasterXML/jackson) filter to conditionally control access to fields based on policies. Three main interfaces drive this flow:

* **PrincipalProvider** interface will identify the current logged in user (a.ka., the Principal). The default auto-configuration will use Spring Security's SecurityContextHolder. To provide your own custom implementation register a bean of type PrincipalProvider. 
* **EntityCreatedByProvider** interface will identify the owner of the serialized object. The default auto-configuration will use the field annotated by Spring Data's **@CreatedBy**. To provide your own custom implementation register a bean of type EntityCreatedByProvider.
* **FieldSecurityPolicy** and **ContextAwareFieldSecurityPolicy** interfaces define policies for permitting a field. A field can have multiple policies combined with logic to determine a field's permissiveness. 

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
    @SecureField( policies = {GroupPolicy.class},
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
 
## Debugging

You can increase the logging level to inspect how the security policies are being processed.

Edit you **application.properties** with:
```
logging.level.com.jahnelgroup.jackson.security=DEBUG
```