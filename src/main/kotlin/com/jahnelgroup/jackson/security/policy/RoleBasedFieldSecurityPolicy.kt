package com.jahnelgroup.jackson.security.policy

import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.jahnelgroup.jackson.security.principal.PrincipalProvider
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import org.springframework.security.core.context.SecurityContextHolder

class RoleBasedFieldSecurityPolicy : ContextAwareFieldSecurityPolicy {

    companion object {
        private val log = LoggerFactory.getLogger(RoleBasedFieldSecurityPolicy::class.java)
    }

    var roles = emptyArray<String>()
    var roleLogic : EvalulationLogic = EvalulationLogic.AND

    // TODO: How can we have the auto-generated setter satisfy the interface?
    private var applicationContext: ApplicationContext? = null
    override fun setApplicationContext(applicationContext: ApplicationContext) {
        this.applicationContext = applicationContext
    }

    override fun permitAccess(writer: PropertyWriter, target: Any, targetCreatedByUser: String?, currentPrincipalUser: String?): Boolean {
        // user isn't logged in
        if( roles.isNotEmpty() && getPrincipal() == null ){
            return false
        }

        var permit = true
        val formattedRoles : List<String> = roles.map {
            if (it.startsWith("ROLE_")) it else "ROLE_" + it
        }

        when( roleLogic ) {

            EvalulationLogic.AND ->
                permit = formattedRoles.takeWhile {
                    var passed = getRoles()!!.contains(it)
                    log.debug("Role ${ if (passed) "Passed" else "Failed" }: $it")
                    return passed // keep going while it passes
                }.size == roles.size // passed all roles

            EvalulationLogic.OR ->
                for(it in formattedRoles) {
                    var passed = getRoles()!!.contains(it)
                    log.debug("Role ${ if (passed) "Passed" else "Failed" }: $it")
                    return permit.or(passed) // keep going while it passes
                }

            EvalulationLogic.XOR ->
                formattedRoles.forEach {
                    var passed = getRoles()!!.contains(it)
                    log.debug("Role ${ if (passed) "Passed" else "Failed" }: $it")
                    return permit.xor(passed) // keep going while it passes
                }

        }

        return permit
    }

    fun getPrincipalProvider() = applicationContext!!.getBean(PrincipalProvider::class.java)
    fun getPrincipal() = getPrincipalProvider()?.getCurrentPrincipal()
    fun getRoles() = getPrincipalProvider()?.getRoles()

}