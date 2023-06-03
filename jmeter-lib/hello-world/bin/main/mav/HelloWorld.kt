package mav

import org.slf4j.Logger
import org.slf4j.LoggerFactory

class HelloWorld {

    private val logger: Logger = LoggerFactory.getLogger(HelloWorld::class.java)

    fun sayHello() {
        logger.info("Hello World!")
        logger.info("Hello World!")
    }

}