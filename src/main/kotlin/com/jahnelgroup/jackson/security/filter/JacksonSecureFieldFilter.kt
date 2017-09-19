package com.jahnelgroup.jackson.security.filter

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.configuration.CreatedByAware
import com.jahnelgroup.jackson.security.policy.PolicyLogic
import org.slf4j.LoggerFactory
import org.springframework.security.core.context.SecurityContextHolder

class JacksonSecureFieldFilter (
    private val globalCreatedBy: CreatedByAware
) : SimpleBeanPropertyFilter(){

    companion object {
        private val log = LoggerFactory.getLogger(JacksonSecureFieldFilter::class.java)
    }

    override fun serializeAsField(pojo: Any, jgen: JsonGenerator, provider: SerializerProvider, writer: PropertyWriter) {
        val secureField : SecureField? = writer.findAnnotation(SecureField::class.java)

        // the field is protected
        if(secureField != null){

            if( log.isDebugEnabled ){
                log.debug("SecureField: target=${pojo.javaClass.name}, field=${writer.member.name}")
            }

            //val createdByAware = secureField.createdBy ?: globalCreatedBy
            val createdByUser : String? = globalCreatedBy.getCreatedBy(pojo)
            val currentPrincipalUser = SecurityContextHolder.getContext().authentication.name

            if( executePolicies(secureField, writer, pojo, createdByUser, currentPrincipalUser) ){
                writer.serializeAsField(pojo, jgen, provider)
            }
        }

        // no protection, just write it out
        else{
            writer.serializeAsField(pojo, jgen, provider)
        }
    }

    private fun executePolicies(secureField: SecureField, writer: PropertyWriter, pojo: Any, createdByUser: String?, currentPrincipalUser: String?): Boolean {
        var permit = false

        if (secureField.policyLogic == PolicyLogic.AND) {
            // passed all the policies
            permit = secureField.policies.takeWhile {
                it::javaObjectType.get().newInstance().permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
            }.size == secureField.policies.size
        }

        else if (secureField.policyLogic == PolicyLogic.OR) {
            // passed at least once policy
            permit = secureField.policies.takeWhile {
                !it::javaObjectType.get().newInstance().permitAccess(writer, pojo, createdByUser, currentPrincipalUser)
            }.size != secureField.policies.size
        }

        else if (secureField.policyLogic == PolicyLogic.XOR) {
            // passed only one policy
            secureField.policies.forEach {
                permit = permit.xor(it::javaObjectType.get().newInstance().permitAccess(writer, pojo, createdByUser, currentPrincipalUser))
            }
        }

        return permit
    }

}