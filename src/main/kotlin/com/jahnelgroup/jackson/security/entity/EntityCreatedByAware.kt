package com.jahnelgroup.jackson.security.entity

/**
 * EntityCreatedByAware
 */
interface EntityCreatedByAware {

    fun getCreatedBy(target: Any) : String

}