package de.ptrckkkk.SpringSecurityCsrfSpaPossibleBug.controller

import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class SampleController {

    @PostMapping(produces = [MediaType.TEXT_PLAIN_VALUE])
    @RequestMapping("/hello")
    fun postHello(): String = "Hello, there"

}
