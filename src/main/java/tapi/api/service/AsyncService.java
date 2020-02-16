package tapi.api.service;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AsyncService
{
    private List<UDPClient> udpClients;
    Map<BigInteger, UDPClientInstance> tokenToClient = new ConcurrentHashMap<>();
    Map<String, List<UDPClientInstance>> addressToClient = new ConcurrentHashMap<>();
    Map<String, Integer> IoTAddrToQueryID = new ConcurrentHashMap<>();

    private static Logger log = LoggerFactory.getLogger(AsyncService.class);

    private static int UDP_PORT = 5001;
    private static int UDP_TOP_PORT = 5004;

    private UDPClientInstance getLatestClient(String ethAddress)
    {
        List<UDPClientInstance> clients = addressToClient.get(ethAddress);
        if (clients != null && clients.size() > 0) return clients.get(clients.size() - 1);
        else return null;
    }

    @Autowired
    private RestTemplate restTemplate;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public AsyncService()
    {
        udpClients = new ArrayList<>();
        //client = new UDPClient();
        try
        {
            for (int port = UDP_PORT; port <= UDP_TOP_PORT; port++)
            {
                UDPClient client = new UDPClient();
                client.init(port);
                client.start();
                udpClients.add(client);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        System.out.println("UDP server started");
    }

    public CompletableFuture<String> getResponse(String address, String method,
                                                 MultiValueMap<String, String> argMap) throws InterruptedException, IOException
    {
        UDPClientInstance instance = getLatestClient(address.toLowerCase());
        if (instance == null) return CompletableFuture.completedFuture("No device found");
        int methodId  = instance.connectedClient.sendToClient(instance, method, argMap);
        if (methodId == -1) return CompletableFuture.completedFuture("API send error");
        int resendIntervalCounter = 0;
        int resendCount = 10;
        boolean responseReceived = false;
        while (!responseReceived && resendCount > 0)
        {
            Thread.sleep(10);
            instance = getLatestClient(address.toLowerCase());
            if (resendIntervalCounter++ > 100)
            {
                resendIntervalCounter = 0;
                instance.connectedClient.reSendToClient(instance, methodId);
                resendCount--;
            }

            if (instance != null && instance.hasResponse(methodId)) responseReceived = true;
        }

        if (resendCount == 0)
        {
            System.out.println("Timed out");
        }
        else
        {
            System.out.println("Received: (" + methodId + ") " + instance.responses.get(methodId));
        }

        return CompletableFuture.completedFuture(instance.getResponse(methodId));
    }

    public CompletableFuture<String> getDeviceAddress(String ipAddress) throws UnknownHostException
    {
        boolean      useFilter    = isLocal(ipAddress);
        InetAddress  inetAddress  = InetAddress.getByName(ipAddress);
        StringBuilder sb = new StringBuilder();
        sb.append("Devices found on IP address: ");
        sb.append(ipAddress);
        byte[]       filter;
        boolean foundAddr = false;

        //filterConnections();

        if (useFilter)
        {
            filter = inetAddress.getAddress();
            filter[3] = 0;
            inetAddress = InetAddress.getByAddress(filter);
        }

        for (List<UDPClientInstance> instances : addressToClient.values())
        {
            UDPClientInstance instance = instances.get(instances.size() - 1);
            byte[] ipBytes = instance.IPAddress.getAddress();
            if (useFilter) ipBytes[3] = 0;
            InetAddress instanceAddr = InetAddress.getByAddress(ipBytes);
            if (instanceAddr.equals(inetAddress))
            {
                foundAddr = true;
                sb.append("</br>");
                sb.append(instance.ethAddress);
            }
        }

        if (!foundAddr)
        {
            sb.append("</br>No devices");
        }

        return CompletableFuture.completedFuture(sb.toString());
    }

    private boolean isLocal(String ipAddress) throws UnknownHostException
    {
        InetAddress inetAddress = InetAddress.getByName(ipAddress);
        byte[] filter = inetAddress.getAddress();
        return filter[0] == (byte) 192 && filter[1] == (byte) 168;
    }

    private class UDPClientInstance
    {
        public String ethAddress;
        public InetAddress IPAddress;
        public int port;
        public long validationTime;
        public long sessionRenewTime;
        public byte[] sessionToken;
        public int unknownCount = 0;
        public UDPClient connectedClient;

        public boolean validated;
        private Map<Integer, String> responses;
        private Map<Integer, byte[]> currentQueries;

        public UDPClientInstance(InetAddress iAddr, int p, String eAddress)
        {
            ethAddress = eAddress;
            IPAddress = iAddr;
            port = p;
            validated = false;
            responses = new ConcurrentHashMap<>();
            currentQueries = new ConcurrentHashMap<>();
            sessionRenewTime = System.currentTimeMillis();

            validationTime = 0;
        }

        public BigInteger generateNewSessionToken(SecureRandom secRand)
        {
            BigInteger tokenValue = BigInteger.valueOf(secRand.nextLong());
            sessionToken = Numeric.toBytesPadded(tokenValue, 8);
            sessionRenewTime = System.currentTimeMillis();
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

        public void setResponse(int methodId, String r)
        {
            responses.put(methodId, r);
            currentQueries.remove(methodId);
        }

        public void setQuery(byte packetId, byte[] packet, byte payloadSize)
        {
            packet[2] = payloadSize;
            currentQueries.put((int)packetId, packet);
        }

        // Connection is valid if recently validated, or is less than 60 seconds since last validation (to handle instances where the instruction comes between validation sessions)
        public boolean isValid()
        {
            return validated || (System.currentTimeMillis() - validationTime) < 60 * 1000;
        }
    }

    private static final int CLIENT_REQUEST_AUTHENTICATION = 0;
    private static final int CLIENT_AUTHENTICATION = 1;
    private static final int CLIENT_API_CALL_RETURN = 2;
    private static final int CLIENT_PING = 3;
    private static final int RENEGOTIATE = 5;

    private static final byte SERVER_CHALLENGE = 0;
    private static final byte SIGNATURE_VALIDATE = 1;
    private static final byte API_CALL = 2;
    private static final byte PONG = 3;


    private class UDPClient extends Thread
    {
        private DatagramSocket socket;
        private byte[] receiveData;
        private boolean running;
        private SecureRandom secRand;

        public void init(int port) throws SocketException
        {
            receiveData  = new byte[1024];
            secRand = new SecureRandom();
            secRand.setSeed(System.currentTimeMillis());
            socket = new DatagramSocket(port);
        }

        public void run()
        {
            byte[] rcvSessionToken = new byte[8];
            running = true;

            while (running)
            {
                try
                {
                    DatagramPacket packet
                            = new DatagramPacket(receiveData, receiveData.length);
                    socket.receive(packet);

                    ByteArrayInputStream bas = new ByteArrayInputStream(packet.getData());
                    DataInputStream inputStream = new DataInputStream(bas);

                    InetAddress address = packet.getAddress();
                    int         port    = packet.getPort();

                    byte type = inputStream.readByte();             //1 byte
                    inputStream.read(rcvSessionToken);              //8 bytes
                    BigInteger tokenValue = Numeric.toBigInt(rcvSessionToken);
                    int length = (inputStream.readByte() & 0xFF);   //1 byte (payload length)
                    byte[] payload = new byte[length];
                    inputStream.read(payload);                      //payload bytes
                    UDPClientInstance thisClient;
                    inputStream.close();
                    bas.close();

                    thisClient = tokenToClient.get(tokenValue);

                    if (thisClient != null)
                    {
                        if (!thisClient.IPAddress.equals(address) || thisClient.port != port)
                        {
                            //invalidate client, send re-negotiate packet to client if client doesn't reply correctly
                            //thisClient.validated = false;
                            System.out.println("IP wrong");
                            thisClient.port = port;
                            thisClient.IPAddress = address;
                        }
                        thisClient.connectedClient = this;
                    }

                    switch (type)
                    {
                        case CLIENT_REQUEST_AUTHENTICATION: //request a random
                            if (thisClient == null)
                            {
                                if (tokenValue.equals(BigInteger.ZERO)) //new client
                                {
                                    thisClient = new UDPClientInstance(address, port, "");
                                    tokenValue = thisClient.generateNewSessionToken(secRand);
                                    log(address, "Client login: " + Numeric.toHexString(thisClient.sessionToken));
                                    sendToClient(thisClient, SERVER_CHALLENGE, thisClient.sessionToken, rcvSessionToken);
                                    tokenToClient.put(tokenValue, thisClient);
                                    log(address, "Send Connection Token: " + Numeric.toHexString(thisClient.sessionToken));
                                }
                                else
                                {
                                    log(address, "Unknown client: " + Numeric.toHexString(rcvSessionToken));
                                    break;
                                }
                            }
                            else
                            {
                                log(address, "Re-Send Connection Token: " + Numeric.toHexString(thisClient.sessionToken));
                                sendToClient(thisClient, SERVER_CHALLENGE, thisClient.sessionToken, rcvSessionToken);
                            }

                            break;

                        case CLIENT_AUTHENTICATION: //address
                            log(address, "Receive Verification From: " + Numeric.toHexString(rcvSessionToken));

                            //recover signature
                            if (thisClient != null && payload.length == 65)
                            {
                                String recoveredAddr = recoverAddressFromSignature(rcvSessionToken, payload);
                                if (recoveredAddr.length() == 0) break;
                                if (thisClient.ethAddress.length() == 0)
                                {
                                    log(address, "Validate client: " + recoveredAddr);
                                    thisClient.ethAddress = recoveredAddr;
                                }
                                else if (recoveredAddr.equalsIgnoreCase(thisClient.ethAddress))
                                {
                                    log(address, "Renew client.");
                                }
                                else
                                {
                                    log(address, "Reject.");
                                    break;
                                }

                                if (!thisClient.validated)
                                {
                                    log(address, "Validated: " + recoveredAddr);
                                    thisClient.validationTime = System.currentTimeMillis();
                                    log(address, "New Session T: " + Numeric.toHexString(thisClient.sessionToken));
                                    thisClient.unknownCount = 0;
                                    thisClient.validated = true;
                                    addToAddresses(recoveredAddr.toLowerCase(), thisClient);
                                    tokenToClient.put(tokenValue, thisClient);
                                }

                                sendToClient(thisClient, SIGNATURE_VALIDATE, thisClient.sessionToken);
                            }
                            break;

                        case CLIENT_API_CALL_RETURN:
                            int methodId = payload[0];
                            payload = Arrays.copyOfRange(payload, 1, payload.length);
                            String payloadString = new String(payload);
                            log(address, "RCV Message: " + Numeric.toHexString(rcvSessionToken));

                            if (thisClient != null)
                            {
                                log(address, "Receive: MethodId: " + methodId + " : " + payloadString + " Client #" + Numeric.toHexString(thisClient.sessionToken));
                                thisClient.setResponse(methodId, payloadString);
                            }
                            else
                            {
                                log(address, "Inner Receive, client not valid: " + payloadString + " : 0x" + tokenValue.toString(16));
                            }
                            break;

                        case CLIENT_PING:
                            //ping from client, respond with PONG
                            if (thisClient == null) break;
                            sendToClient(thisClient, PONG, thisClient.sessionToken, rcvSessionToken);
                            log(address, "PING -> PONG (" + Numeric.toHexString(rcvSessionToken) + ")");
                            break;
                        default:
                            break;
                    }
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                    running = false;
                }
            }
        }

        private void addToAddresses(String recoveredAddr, UDPClientInstance thisClient)
        {
            List<UDPClientInstance> addrList = addressToClient.get(recoveredAddr);
            if (addrList == null)
            {
                addrList = new ArrayList<>();
                addressToClient.put(recoveredAddr, addrList);
            }
            else
            {
                //check for out of date client
                if (addrList.size() >= 3)
                {
                    UDPClientInstance oldClient = addrList.get(0);
                    log(oldClient.IPAddress, "Removing client from addr map #" + Numeric.toHexString(oldClient.sessionToken));
                    addrList.remove(oldClient);
                    //remove this guy from main list too
                    if (tokenToClient.containsKey(Numeric.toBigInt(oldClient.sessionToken)))
                    {
                        tokenToClient.remove(Numeric.toBigInt(oldClient.sessionToken));
                        log(oldClient.IPAddress, "Removing client from token map #" + Numeric.toHexString(oldClient.sessionToken));
                    }
                }
            }
            addrList.add(thisClient);
        }

        public void sendToClient(UDPClientInstance instance, byte type, byte[] stuffToSend) throws IOException
        {
            sendToClient(instance, type, stuffToSend, null);
        }

        //transmit back
        public void sendToClient(UDPClientInstance instance, byte type, byte[] stuffToSend, byte[] extraToSend) throws IOException
        {
            ByteArrayOutputStream bas          = new ByteArrayOutputStream();
            DataOutputStream      outputStream = new DataOutputStream(bas);

            int totalPacketLength = 2 + stuffToSend.length;
            if (extraToSend != null) totalPacketLength += extraToSend.length;
            outputStream.writeByte(type);
            outputStream.writeByte((byte)totalPacketLength - 2);
            outputStream.write(stuffToSend);
            if (extraToSend != null) outputStream.write(extraToSend);
            outputStream.flush();
            outputStream.close();

            DatagramPacket packet = new DatagramPacket(bas.toByteArray(), totalPacketLength, instance.IPAddress, instance.port);

            try
            {
                socket.send(packet);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }

        public void reSendToClient(UDPClientInstance instance, int methodId) throws IOException
        {
            if (instance != null && instance.currentQueries.get(methodId) != null)
            {
                System.out.println("Re-Send to client: " + methodId + " : " + Numeric.toHexString(instance.sessionToken));
                byte[] packetBytes = instance.currentQueries.get(methodId);
                DatagramPacket packet = new DatagramPacket(packetBytes, packetBytes.length, instance.IPAddress, instance.port);
                socket.send(packet);
            }
        }

        public int sendToClient(UDPClientInstance instance, String method,
                                              MultiValueMap<String, String> argMap) throws IOException
        {
            int packetId = -1;
            if (instance != null)
            {
                //send message
                ByteArrayOutputStream bas          = new ByteArrayOutputStream();
                DataOutputStream      outputStream = new DataOutputStream(bas);

                packetId = IoTAddrToQueryID.getOrDefault(instance.ethAddress, 0);
                if (++packetId == 256) packetId = 0;
                IoTAddrToQueryID.put(instance.ethAddress, packetId);

                log(instance.IPAddress, "Create API call: " + method + " #" + packetId);

                outputStream.writeByte(API_CALL);
                outputStream.writeByte((byte)packetId);
                outputStream.writeByte((byte)0);

                int payloadSize = 0;

                payloadSize += writeValue(outputStream, method);

                for (String key : argMap.keySet())
                {
                    payloadSize += writeValue(outputStream, key);
                    String param = "";
                    if (argMap.get(key).size() > 0)
                    {
                        param = argMap.get(key).get(0);
                    }
                    payloadSize += writeValue(outputStream, param);
                }

                outputStream.flush();
                outputStream.close();

                instance.setQuery((byte)packetId, bas.toByteArray(), (byte)payloadSize);
                byte[] packetBytes = instance.currentQueries.get((int)packetId);

                DatagramPacket packet = new DatagramPacket(packetBytes, packetBytes.length, instance.IPAddress, instance.port);

                socket.send(packet);
            }

            return packetId;
        }

        private int writeValue(DataOutputStream outputStream, String value) throws IOException
        {
            int writeLength = 1;
            outputStream.writeByte((byte)value.length());
            outputStream.write(value.getBytes());
            writeLength += value.length();
            return writeLength;
        }
    }

    private String recoverAddressFromSignature(byte[] rcvSessionToken, byte[] payload)
    {
        String recoveredAddr = "";
        try
        {
            Sign.SignatureData sigData = sigFromByteArray(payload);
            //recover address from signature
            BigInteger recoveredKey  = Sign.signedMessageToKey(rcvSessionToken, sigData);
            recoveredAddr = "0x" + Keys.getAddress(recoveredKey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return recoveredAddr;
    }

    public static Sign.SignatureData sigFromByteArray(byte[] sig)
    {
        if (sig.length < 64 || sig.length > 65) return null;

        byte   subv = sig[64];
        if (subv < 27) subv += 27;

        byte[] subrRev = Arrays.copyOfRange(sig, 0, 32);
        byte[] subsRev = Arrays.copyOfRange(sig, 32, 64);
        return new Sign.SignatureData(subv, subrRev, subsRev);
    }

    private void log(InetAddress addr, String msg)
    {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
        LocalDateTime     now = LocalDateTime.now();
        System.out.println(dtf.format(now) + ":" + addr.getHostAddress() + ": " + msg);
    }
}

