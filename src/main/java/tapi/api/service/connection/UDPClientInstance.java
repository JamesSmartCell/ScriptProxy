package tapi.api.service.connection;

import org.springframework.util.MultiValueMap;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by JB on 17/02/2020.
 */
public class UDPClientInstance
{
    private String ethAddress;
    private InetAddress IPAddress;
    int port;
    private long validationTime;
    private byte[] sessionToken;
    int unknownCount = 0;
    private UDPClient connectedClient;

    boolean validated;
    private Map<Integer, String> responses;
    private Map<Integer, byte[]> currentQueries;

    UDPClientInstance(InetAddress iAddr, int p, String eAddress)
    {
        ethAddress = eAddress;
        IPAddress = iAddr;
        port = p;
        validated = false;
        responses = new ConcurrentHashMap<>();
        currentQueries = new ConcurrentHashMap<>();

        validationTime = System.currentTimeMillis();
    }

    BigInteger generateNewSessionToken(SecureRandom secRand)
    {
        BigInteger tokenValue = BigInteger.valueOf(secRand.nextLong());
        sessionToken = Numeric.toBytesPadded(tokenValue, 8);
        validated = false;
        return Numeric.toBigInt(sessionToken);
    }

    public boolean hasResponse(int methodId)
    {
        return responses.get(methodId) != null;
    }

    public String getResponse(int methodId)
    {
        String resp = responses.get(methodId);
        responses.remove(methodId);
        currentQueries.remove(methodId);
        return resp;
    }

    void setResponse(int methodId, String r)
    {
        responses.put(methodId, r);
        currentQueries.remove(methodId);
    }

    void setQuery(byte packetId, byte[] packet, byte payloadSize)
    {
        packet[2] = payloadSize;
        currentQueries.put((int)packetId, packet);
    }

    byte[] getQuery(int methodId)
    {
        return currentQueries.get(methodId);
    }

    public InetAddress getIPAddress()
    {
        return IPAddress;
    }

    public String getEthAddress()
    {
        return ethAddress;
    }

    public byte[] getSessionToken()
    {
        return sessionToken;
    }

    void setEthAddress(String recoveredAddr)
    {
        ethAddress = recoveredAddr;
    }

    public String getSessionTokenStr()
    {
        return Numeric.toHexString(sessionToken);
    }

    public long getValidationTime()
    {
        return validationTime;
    }

    void setValidationTime()
    {
        this.validationTime = System.currentTimeMillis();
    }

    public int sendToClient(String method, MultiValueMap<String, String> argMap) throws IOException
    {
        return connectedClient.sendToClient(this, method, argMap);
    }

    void setConnectedClient(UDPClient udpClient)
    {
        connectedClient = udpClient;
    }

    public void reSendToClient(int methodId) throws IOException
    {
        connectedClient.reSendToClient(this, methodId);
    }
}
