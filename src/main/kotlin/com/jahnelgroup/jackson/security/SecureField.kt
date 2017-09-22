package com.jahnelgroup.jackson.security

import com.jahnelgroup.jackson.security.policy.CreatedByFieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.FieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.PolicyLogic
import kotlin.reflect.KClass

/**
 * Declares a field to be protected from being serialized by Jackson. Access
 * controls are based on [FieldSecurityPolicy] policies which can be combined
 * together with [PolicyLogic].
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
@Target(AnnotationTarget.FIELD)
@Retention(AnnotationRetention.RUNTIME)
annotation class SecureField(

        /**
     * The list of [FieldSecurityPolicy] policies that must be met
     * in order to permit access to a field. The default policy is
     * the [CreatedByFieldSecurityPolicy] policy.
     */
    val policies: Array<KClass<out FieldSecurityPolicy>> = arrayOf(CreatedByFieldSecurityPolicy::class),

        /**
     * The logic by which the [SecureField.policies] are evaluated
     * together. The default logic is AND.
     */
    val policyLogic: PolicyLogic = PolicyLogic.AND

)
