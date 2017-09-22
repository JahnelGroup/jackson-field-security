package com.jahnelgroup.jackson.security.entity

import org.springframework.data.annotation.CreatedBy
import org.springframework.util.ReflectionUtils

/**
 * SpringDataEntityCreatedByAware
 */
class SpringDataEntityCreatedByAware : EntityCreatedByAware {

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