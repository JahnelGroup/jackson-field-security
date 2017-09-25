package com.jahnelgroup.jackson.security.policy

/**
 * Defines the type of logic that policies or roles can be combined
 * together with.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
enum class EvalulationLogic {

    /**
     * All must permit access.
     */
    AND,

    /**
     * At least one must permit access.
     */
    OR,

    /**
     * Exactly one must permit access.
     */
    XOR
}