# Jackson Field Security

**Provides a simple way to add field level security to your Spring Boot applications with the help of Jackson filters.**

## Prerequisites

This library depends on Jackson, Spring Security and Spring Data.

## Getting Started

Add the library to your application with Maven or Gradle.

Maven:
```xml
<dependency>
    <groupId>com.jahnelgroup.jackson</groupId>
    <artifactId>jackson-field-security</artifactId>
    <version>1.0.1</version>
</dependency>
```

Gradle:

```
compile('com.jahnelgroup.jackson:jackson-field-security:1.0.1')
```

## How it works

This library registers a [Jackson](https://github.com/FasterXML/jackson) filter to conditionally control access to fields based on policies. Three main interface's drive this flow:

* **PrincipalAware** interface will identify the current logged in user (a.ka., the Principal). The default auto-configuration will use Spring Security's SecurityContextHolder. To provide your own custom implementation register a bean of type PrincipalAware. 
* **EntityCreatedByAware** interface will identify the owner of the serialized object. The default auto-configuration will use the field annotated by Spring Data's **@CreatedBy**. To provide your own custom implementation just register a bean of type EntityCreatedByAware.
* **FieldSecurityPolicy** interface defines a policy for permitting a field. A field can have multiple policies combined with logic to determine a field's permissiveness. 

## Usage

Annotate your class with **@JsonFilter("securityFilter")** and the fields that need to be protected with **@SecureField**. Any entity with a field annotated by @SecureField **must** have the class annotated with @JsonFilter otherwise the security filter will not be invoked.

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

    // by default this will use the CreatedByFieldSecurityPolicy
    // which compares the logged in user against the @CreatedBy field. 
    @SecureField        
    String mySecret;
    
    // you can specify a list of custom policies, here we are 
    // protecting a field that can be seen by anyone in the same group
    @SecureField( policies = {GroupPolicy.class} )     
    String groupSecret;    
    
}
```

Here is a possible custom GroupPolicy:

```java
class CreatedByFieldSecurityPolicy implements FieldSecurityPolicy {

    private ApplicationContext appContext;

    public boolean permitAccess(PropertyWriter writer, Object target, 
        String targetCreatedByUser, String currentPrincipalUser) {
        
        return target instanceof User && 
            ((User)target).getGroupIds().stream()
                .anyMatch(getPrincipalGroupIds(currentPrincipalUser));
       
    }
         
    public void setApplicationContext(ApplicationContext appContext){
        this.appContext = appContext;   
    }
    
    private List<Long> getPrincipalGroupIds(String currentPrincipalUser){
        UserService userService = (UserService) applicationContext.getBean("userService");
        return userService.findByUsername(currentPrincipalUser).getGroupIds();
    }

}
```
 