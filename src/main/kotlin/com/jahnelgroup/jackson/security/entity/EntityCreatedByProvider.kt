package com.jahnelgroup.jackson.security.entity

/**
 * Defines the specification for determining the creator/owner of
 * the target POJO.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
interface EntityCreatedByProvider {

    /**
     * @return the creator/owner of the target POJO
     */
    fun getCreatedBy(target: Any) : String

}