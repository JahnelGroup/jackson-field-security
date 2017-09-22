package com.jahnelgroup.jackson.security.entity

import org.springframework.data.annotation.CreatedBy
import org.springframework.util.ReflectionUtils

/**
 * Provider that will use Spring Data's [CreatedBy] annotation to
 * identify the owner of an entity being serialized.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
class SpringDataEntityCreatedByProvider : EntityCreatedByProvider {

    override fun getCreatedBy(target: Any): String {
        // looping to collect all fields from base type and all super types
        // then spin through collection to find the field

        var createdByField = target.javaClass.declaredFields.firstOrNull {
            // first try to find the annotation on the base class
            it.isAnnotationPresent(CreatedBy::class.java)
        } ?:
        target.javaClass.superclass.declaredFields.firstOrNull {
            // else check the super class fields
            it.isAnnotationPresent(CreatedBy::class.java)
        }

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