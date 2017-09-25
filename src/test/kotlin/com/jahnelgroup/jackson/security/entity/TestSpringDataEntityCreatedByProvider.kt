package com.jahnelgroup.jackson.security.entity

import org.assertj.core.api.Assertions.*
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.data.annotation.CreatedBy
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
class TestSpringDataEntityCreatedByProvider {

    class NoCreatedByAnnotation {
        var firstName = "Steven"
        var lastName = "Zgaljic"
    }

    class CreatedByAnnotation {
        var firstName = "Steven"
        var lastName = "Zgaljic"
        @CreatedBy var username : String? = "szgaljic"
    }

    var provider = SpringDataEntityCreatedByProvider()

    @Test
    fun `Returns null when no field is annotated with @CreatedBy`(){
        assertThat(provider.getCreatedBy(NoCreatedByAnnotation())).isNull()
    }

    @Test
    fun `Returns the value of field annotated with @CreatedBy when it's not null`(){
        assertThat(provider.getCreatedBy(CreatedByAnnotation())).isEqualTo("szgaljic")
    }

    @Test
    fun `Returns empty string of field annotated with @CreatedBy when it's an empty string`(){
        var c = CreatedByAnnotation()
        c.username = ""
        assertThat(provider.getCreatedBy(c)).isEqualTo("")
    }

    @Test
    fun `Returns null when @CreatedBy is null`(){
        var c = CreatedByAnnotation()
        c.username = null
        assertThat(provider.getCreatedBy(c)).isNull()
    }

}