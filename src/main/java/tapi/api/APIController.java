package tapi.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.servlet.http.HttpServletRequest;

import tapi.api.service.AsyncService;


@Controller
@RequestMapping("/api")
public class APIController
{
    private class APIData
    {
        public String fullApiCall;
        public String response;

        public APIData(String call)
        {
            fullApiCall = call;
            response = "";
        }
    }

    private Map<String, APIData> responses = new HashMap<>();

    @Autowired
    public APIController()
    {

    }

    @Autowired
    private AsyncService service;

    @CrossOrigin(origins= {"*"}, maxAge = 4800, allowCredentials = "false" )
    @RequestMapping(value = "/0x{Address}/{method}", method = { RequestMethod.GET, RequestMethod.POST })
    public ResponseEntity pushCheck(@PathVariable("Address") String address,
                                    @PathVariable("method") String method) throws InterruptedException, ExecutionException, IOException
    {
        ServletUriComponentsBuilder args = ServletUriComponentsBuilder.fromCurrentRequest();
        address = "0x" + address;
        System.out.println("ADDRESS: " + address);
        System.out.println("METHOD: " + method);
        UriComponents comps = args.build();
        MultiValueMap<String, String> argMap = comps.getQueryParams();
        CompletableFuture<String> deviceAPIreturn = service.getResponse(address, method, argMap);
        CompletableFuture.allOf(deviceAPIreturn).join();

        return new ResponseEntity<>(deviceAPIreturn.get(), HttpStatus.CREATED);
    }

    @RequestMapping(value = "getEthAddress", method = { RequestMethod.GET, RequestMethod.POST })
    public ResponseEntity getAddresses(HttpServletRequest request) throws InterruptedException, ExecutionException, IOException
    {
        String ipAddress = request.getRemoteAddr();
        CompletableFuture<String> deviceAPIreturn = service.getDeviceAddress(ipAddress);
        CompletableFuture.allOf(deviceAPIreturn).join();

        return new ResponseEntity<>(deviceAPIreturn.get(), HttpStatus.CREATED);
    }
}
