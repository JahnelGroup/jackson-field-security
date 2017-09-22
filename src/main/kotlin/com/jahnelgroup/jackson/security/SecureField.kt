package com.jahnelgroup.jackson.security

import com.jahnelgroup.jackson.security.policy.CreatedByFieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.FieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.PolicyLogic
import kotlin.reflect.KClass

/**
 * Annotation to protect fields from being serialized by Jackson based on FieldSecurityPolicy
 */
@Target(AnnotationTarget.FIELD)
@Retention(AnnotationRetention.RUNTIME)
annotation class SecureField(

    val policies: Array<KClass<out FieldSecurityPolicy>> = arrayOf(CreatedByFieldSecurityPolicy::class),
    val policyLogic: PolicyLogic = PolicyLogic.AND

)
