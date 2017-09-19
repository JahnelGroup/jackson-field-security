package com.jahnelgroup.jackson.security.configuration

interface CreatedByAware {

    fun getCreatedBy(target: Any) : String

}