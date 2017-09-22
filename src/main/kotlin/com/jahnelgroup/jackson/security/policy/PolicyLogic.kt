package com.jahnelgroup.jackson.security.policy

/**
 * Defines the type of logic that policies can be combined together with.
 *
 * @author Steven Zgaljic
 * @since 1.0.0
 */
enum class PolicyLogic {

    /**
     * All policies must permit access.
     */
    AND,

    /**
     * At least one policy must permit access.
     */
    OR,

    /**
     * Exactly one policy must permit access.
     */
    XOR
}