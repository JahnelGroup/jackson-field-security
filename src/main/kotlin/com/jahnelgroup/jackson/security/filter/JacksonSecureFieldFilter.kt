package com.jahnelgroup.jackson.security.filter

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter
import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.entity.EntityCreatedByProvider
import com.jahnelgroup.jackson.security.policy.ContextAwareFieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.FieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.EvalulationLogic
import com.jahnelgroup.jackson.security.policy.RoleBasedFieldSecurityPolicy
import com.jahnelgroup.jackson.security.principal.PrincipalProvider
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import kotlin.reflect.KClass

/**
 * The main filter that drives processing of the security annotations. 
 */
class JacksonSecureFieldFilter (
        private val applicationContext : ApplicationContext,
        private val globalPrincipalProvider: PrincipalProvider,
        private val globalEntityCreatedByProvider: EntityCreatedByProvider
) : SimpleBeanPropertyFilter(){

    companion object {
        private val log = LoggerFactory.getLogger(JacksonSecureFieldFilter::class.java)
    }

    override fun serializeAsField(pojo: Any, jgen: JsonGenerator, provider: SerializerProvider, writer: PropertyWriter) {
        val secureField : SecureField? = writer.findAnnotation(SecureField::class.java)

        // the field is protected
        if(secureField != null){

            //val createdByAware = secureField.entityCreatedBy ?: globalEntityCreatedByProvider
            val createdByUser : String? = globalEntityCreatedByProvider.getCreatedBy(pojo)
            val currentPrincipalUser : String? = globalPrincipalProvider.getCurrentPrincipal()

            if( executePolicies(secureField, writer, pojo, createdByUser, currentPrincipalUser) ){
                log.debug("Field Permitted: ${writer.name}")
                writer.serializeAsField(pojo, jgen, provider)
            }else{
                log.debug("Field Denied: ${writer.name}")
            }
        }

        // no protection, just write it out
        else{
            log.debug("Field Permitted: ${writer.name}")
            writer.serializeAsField(pojo, jgen, provider)
        }
    }

    private fun executePolicies(secureField: SecureField, writer: PropertyWriter, pojo: Any, createdByUser: String?, currentPrincipalUser: String?): Boolean {
        var permit = false
        val policies = if (secureField.roles.isEmpty()) secureField.policies
            else secureField.policies.plusElement(RoleBasedFieldSecurityPolicy::class)

        log.debug("Executing ${policies.size} policies with evaluation logic ${secureField.policyLogic}")

        if (secureField.policyLogic == EvalulationLogic.AND) {
            // passed all the policies
            permit = policies.takeWhile {
                var passed = initPolicy(secureField, it).permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
                log.debug("Policy ${ if (passed) "Passed" else "Failed" }: ${it::javaObjectType.get().simpleName}")
                return passed // keep going while it passes
            }.size == secureField.policies.size // passed all polices
        }

        else if (secureField.policyLogic == EvalulationLogic.OR) {
            // passed at least once policy
            for(it in policies){
                var passed = initPolicy(secureField, it).permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
                log.debug("Policy ${ if (passed) "Passed" else "Failed" }: ${it::javaObjectType.get().simpleName}")
                permit = permit.or(passed)
                if( permit ) break
            }
        }

        else if (secureField.policyLogic == EvalulationLogic.XOR) {
            // passed only one policy
            policies.forEach {
                var passed = initPolicy(secureField, it).permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
                log.debug("Policy ${ if (passed) "Passed" else "Failed" }: ${it::javaObjectType.get().simpleName}")
                permit = permit.xor(passed) // only one should pass
            }
        }

        return permit
    }

    fun initPolicy(secureField: SecureField, policy : KClass<out FieldSecurityPolicy>) : FieldSecurityPolicy{
        var policyInstance = policy::javaObjectType.get().newInstance()
        if ( policyInstance is ContextAwareFieldSecurityPolicy ){
            policyInstance.setApplicationContext(applicationContext)
        }
        if( policyInstance is RoleBasedFieldSecurityPolicy && secureField.roles.isNotEmpty() ){
            policyInstance.roles = secureField.roles
            policyInstance.roleLogic = secureField.roleLogic
        }
        return policyInstance
    }

}