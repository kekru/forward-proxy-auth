import spock.lang.*
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClientBuilder

class SimplePasswordSpec extends Specification {

    def client

    def setup(){
        client = HttpClientBuilder.create().build()
    }

    def "No token and no password are sent" (){
        given: "something"
        def a = 0

        when: "max is requested"
        def res = client.execute(new HttpGet("http://localhost:8080"))
		

        then: "sdgsg"
         a == 0
        
    }
}