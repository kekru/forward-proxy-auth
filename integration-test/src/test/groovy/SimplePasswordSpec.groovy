import spock.lang.*


class SimplePasswordSpec extends Specification {


    def "abc" (){
        given: "something"
        def a = 0

        when: "max is requested"
        def max = Math.max(a, 10)

        then: "sdgsg"
        max == 10
    }
}