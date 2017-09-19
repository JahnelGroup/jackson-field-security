package com.jahnelgroup.jackson

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@SpringBootApplication
class JacksonFieldSecurityApplication

fun main(args: Array<String>) {
    SpringApplication.run(JacksonFieldSecurityApplication::class.java, *args)
}
