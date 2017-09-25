package com.jahnelgroup.jackson.security.entity

import org.springframework.data.annotation.CreatedBy
import org.springframework.util.ReflectionUtils
import java.lang.reflect.Field

/**
 * Provider that will use Spring Data's [CreatedBy] annotation to
 * identify the owner of an entity being serialized.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
class SpringDataEntityCreatedByProvider : EntityCreatedByProvider {

    override fun getCreatedBy(target: Any): String {
        var createdByField : Field? = null
        ReflectionUtils.doWithFields(target.javaClass,
            {field -> createdByField = field},
            {field -> field.isAnnotationPresent(CreatedBy::class.java) }
        )

        // if it exists return the value
        return when( createdByField != null ){
            true -> {
                ReflectionUtils.makeAccessible(createdByField)
                createdByField?.get(target)?.toString() ?: ""
            }
            false -> ""
        }
    }

}