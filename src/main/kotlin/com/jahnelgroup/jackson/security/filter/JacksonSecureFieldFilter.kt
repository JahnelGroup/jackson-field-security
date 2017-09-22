package com.jahnelgroup.jackson.security.filter

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.entity.EntityCreatedByProvider
import com.jahnelgroup.jackson.security.policy.FieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.PolicyLogic
import com.jahnelgroup.jackson.security.principal.PrincipalProvider
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext

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
                log.debug("Permit: ${writer.name}")
                writer.serializeAsField(pojo, jgen, provider)
            }else{
                log.debug("Deny: ${writer.name}")
            }
        }

        // no protection, just write it out
        else{
            log.debug("Permit (no security): ${writer.name}")
            writer.serializeAsField(pojo, jgen, provider)
        }
    }

    private fun executePolicies(secureField: SecureField, writer: PropertyWriter, pojo: Any, createdByUser: String?, currentPrincipalUser: String?): Boolean {
        var permit = false

        if (secureField.policyLogic == PolicyLogic.AND) {
            // passed all the policies
            permit = secureField.policies.takeWhile {
                var policy : FieldSecurityPolicy = it::javaObjectType.get().newInstance()
                policy.setApplicationContext(applicationContext)
                policy.permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
            }.size == secureField.policies.size
        }

        else if (secureField.policyLogic == PolicyLogic.OR) {
            // passed at least once policy
            permit = secureField.policies.takeWhile {
                var policy : FieldSecurityPolicy = it::javaObjectType.get().newInstance()
                policy.setApplicationContext(applicationContext)
                !policy.permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
            }.size != secureField.policies.size
        }

        else if (secureField.policyLogic == PolicyLogic.XOR) {
            // passed only one policy
            secureField.policies.forEach {
                var policy : FieldSecurityPolicy = it::javaObjectType.get().newInstance()
                policy.setApplicationContext(applicationContext)
                permit = permit.xor(policy.permitAccess(writer, pojo, createdByUser, currentPrincipalUser))
            }
        }

        return permit
    }

}