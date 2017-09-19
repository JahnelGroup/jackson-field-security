package com.jahnelgroup.jackson.security

import com.jahnelgroup.jackson.security.configuration.CreatedByAware
import com.jahnelgroup.jackson.security.policy.CreatedByFieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.FieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.PolicyLogic
import kotlin.reflect.KClass

@Target(AnnotationTarget.FIELD)
@Retention(AnnotationRetention.RUNTIME)
annotation class SecureField(

    val policies: Array<KClass<out FieldSecurityPolicy>> = arrayOf(CreatedByFieldSecurityPolicy::class),
    val policyLogic: PolicyLogic = PolicyLogic.AND,

    val createdBy: KClass<out CreatedByAware>

)
