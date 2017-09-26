package com.jahnelgroup.jackson.security.filter

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.PropertyWriter
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter
import com.jahnelgroup.jackson.security.SecureField
import com.jahnelgroup.jackson.security.entity.EntityCreatedByProvider
import com.jahnelgroup.jackson.security.exception.AccessDeniedExceptionHandler
import com.jahnelgroup.jackson.security.policy.ContextAwareFieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.FieldSecurityPolicy
import com.jahnelgroup.jackson.security.policy.EvalulationLogic
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
        private val globalEntityCreatedByProvider: EntityCreatedByProvider,
        private val accessDeniedExceptionHandler: AccessDeniedExceptionHandler
) : SimpleBeanPropertyFilter(){

    companion object {
        private val log = LoggerFactory.getLogger(JacksonSecureFieldFilter::class.java)
    }

    override fun serializeAsField(pojo: Any, jgen: JsonGenerator, provider: SerializerProvider, writer: PropertyWriter) {
        val secureField : SecureField? = writer.findAnnotation(SecureField::class.java)

        var permit = false

        if(secureField != null){
            permit = executePolicies(secureField, writer, pojo)
        } else {
            permit = true
        }

        if (permit){
            log.debug("Field Permitted: ${writer.name}")
            writer.serializeAsField(pojo, jgen, provider)
        } else {
            log.debug("Field Denied: ${writer.name}")
        }
    }

    private fun executePolicies(secureField: SecureField, writer: PropertyWriter, pojo: Any): Boolean {
        var permit : Boolean? = null

        var policies : List<FieldSecurityPolicy> = getPolicies(secureField)

        log.debug("Executing ${policies.size} policies " +
            "for field ${writer.member.declaringClass}.[${writer.member.name}] " +
            "annotated by @SecureField=$secureField")

        policies@ for(it in policies){

            var passed : Boolean

            try{
                passed = it.permitAccess(secureField, writer, pojo,
                    globalEntityCreatedByProvider.getCreatedBy(pojo),
                    globalPrincipalProvider.getPrincipal())
            } catch(e : Exception){
                log.debug("Exception during policy: ${e.message}")
                passed = accessDeniedExceptionHandler.permitAccess(e)
            }

            log.debug("Policy ${if (passed) "Passed" else "Failed"}: $it")

            when ( secureField.policyLogic ){
                EvalulationLogic.AND -> {
                    permit = permit?.and(passed) ?: passed
                    if(!permit) break@policies
                }
                EvalulationLogic.OR -> {
                    permit = permit?.or(passed) ?: passed
                    if(permit) break@policies
                }
                EvalulationLogic.XOR -> {
                    permit = permit?.xor(passed) ?: passed
                }
            }

        }

        return permit ?: false
    }

    fun getPolicies(secureField: SecureField) : List<FieldSecurityPolicy> {
        val policyClasses = secureField.policyClasses.toList()
        val policyBeans = secureField.policyBeans.map {
            applicationContext.getBean(it, FieldSecurityPolicy::class) as FieldSecurityPolicy
        }.toMutableList()

        if( secureField.roles.isNotEmpty() ){
            policyBeans.add(getPolicyBean("roleBasedFieldSecurityPolicy"))
        }

        // default
        if( policyBeans.isEmpty() && policyClasses.isEmpty() ){
            policyBeans.add(getPolicyBean("createdByFieldSecurityPolicy"))
        }

        // combine together
        var policies : MutableList<FieldSecurityPolicy> = mutableListOf()
        policies.addAll(policyBeans)
        policies.addAll(policyClasses.map {
            initPolicyClass(it)
        })

        return policies
    }

    fun getPolicyBean(policyBeanName : String) : FieldSecurityPolicy =
        applicationContext.getBean(policyBeanName, FieldSecurityPolicy::class)
            as FieldSecurityPolicy

    fun initPolicyClass(policy : KClass<out FieldSecurityPolicy>) : FieldSecurityPolicy{
        var policyInstance = policy::javaObjectType.get().newInstance()
        if ( policyInstance is ContextAwareFieldSecurityPolicy ){
            policyInstance.setApplicationContext(applicationContext)
        }
        return policyInstance
    }

}