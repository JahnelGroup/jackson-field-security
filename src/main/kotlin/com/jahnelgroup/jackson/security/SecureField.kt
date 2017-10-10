package com.jahnelgroup.jackson.security

import com.jahnelgroup.jackson.security.policy.*
import kotlin.reflect.KClass

/**
 * Declares a field to be protected from being serialized by Jackson. Access
 * controls are based on [FieldSecurityPolicy] policies which can be combined
 * together with [EvalulationLogic].
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
@Target(AnnotationTarget.FIELD)
@Retention(AnnotationRetention.RUNTIME)
@Repeatable
annotation class SecureField(

    /**
     * The list of [FieldSecurityPolicy] policies that must be met
     * in order to permit access to a field. The default policy is
     * the [CreatedByFieldSecurityPolicy] policy.
     */
    val policyClasses: Array<KClass<out FieldSecurityPolicy>> = emptyArray(),

    /**
     * Same as [SecureField.policies] but provided as a list of Spring
     * Bean's that implement [FieldSecurityPolicy]. This is useful if
     * you don't want to implement the [ContextAwareFieldSecurityPolicy]
     * interface.
     *
     * This is also how you can adapt into Spring's Global Method Security
     * by annotating the [FieldSecurityPolicy.permitAccess] method with a
     * SpEL expression.
     */
    val policyBeans: Array<String> = emptyArray(),

    /**
     * The logic by which the policies are all evaluated together.
     *
     * The default logic is AND.
     */
    val policyLogic: EvalulationLogic = EvalulationLogic.AND,

    /**
     * The list of user policy that must be met in order to permit
     * access to a field. Providing policy will automatically add the
     * [RoleBasedFieldSecurityPolicy] policy to the policies list.
     */
    val roles : Array<String> = emptyArray(),

    /**
     * The logic by which the policy are all evaluated together.
     *
     * The default logic is AND.
     */
    val roleLogic: EvalulationLogic = EvalulationLogic.AND
)
