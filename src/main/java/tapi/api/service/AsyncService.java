package tapi.api.service;


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
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@Service
public class AsyncService
{
    private UDPClient client;
    private static Logger log = LoggerFactory.getLogger(AsyncService.class);

    private static int UDP_PORT = 5001;

    @Autowired
    private RestTemplate restTemplate;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public AsyncService()
    {
        client = new UDPClient();
        try
        {
            client.init();
            client.start();
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
        UDPClientInstance instance = client.sendToClient(address, method, argMap);
        if (instance == null) return CompletableFuture.completedFuture("null");
        int resendIntervalCounter = 0;
        int resendCount = 5;
        while (!instance.hasResponse() && resendCount > 0)
        {
            Thread.sleep(10);
            if (resendIntervalCounter++ > 100)
            {
                resendIntervalCounter = 0;
                client.reSendToClient(instance);
                resendCount--;
            }
        }

        return CompletableFuture.completedFuture(instance.getResponse());
    }

    private class UDPClientInstance
    {
        public final String ethAddress;
        public InetAddress IPAddress;
        public int port;
        public byte packetId;
        public long lastConnection;
        public long lastRenewal;
        public byte[] sessionToken;
        public byte[] currentQuery;

        public boolean validated;
        private String response;

        public UDPClientInstance(InetAddress iAddr, int p, String eAddress)
        {
            ethAddress = eAddress;
            IPAddress = iAddr;
            port = p;
            validated = false;
            response = null;
            lastRenewal = 0;
            packetId = 0;
            currentQuery = null;

            lastConnection = System.currentTimeMillis();
        }

        public BigInteger generateNewSessionToken(SecureRandom secRand)
        {
            BigInteger tokenValue = BigInteger.valueOf(secRand.nextLong());
            sessionToken = Numeric.toBytesPadded(tokenValue, 8);
            lastRenewal = System.currentTimeMillis();
            validated = false;
            return Numeric.toBigInt(sessionToken);
        }

        public boolean hasResponse()
        {
            return response != null;
        }

        public String getResponse()
        {
            String resp = response;
            response = null;
            return resp;
        }

        public void setResponse(String r)
        {
            response = r;
            currentQuery = null;
        }
    }

    Map<BigInteger, UDPClientInstance> holdingClients = new ConcurrentHashMap<>();
    Map<String, UDPClientInstance> clients = new ConcurrentHashMap<>();

    private class UDPClient extends Thread
    {
        private DatagramSocket socket;
        private byte[] receiveData;
        private boolean running;
        private SecureRandom secRand;

        public void init() throws SocketException
        {
            receiveData  = new byte[1024];
            secRand = new SecureRandom();
            secRand.setSeed(System.currentTimeMillis());
            socket = new DatagramSocket(UDP_PORT);
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
                    int length = (inputStream.readByte() & 0xFF);       //1 byte (payload length)
                    byte[] payload = new byte[length];
                    inputStream.read(payload);                      //payload bytes
                    UDPClientInstance thisClient;
                    inputStream.close();
                    bas.close();

                    switch (type)
                    {
                        case 0: //request a random
                            thisClient = holdingClients.get(tokenValue);
                            if (thisClient == null)
                            {
                                thisClient = new UDPClientInstance(address, port, "");
                                tokenValue = thisClient.generateNewSessionToken(secRand);
                                System.out.println("Issue new token: " + Numeric.toHexString(thisClient.sessionToken));
                            }
                            else
                            {
                                if ((thisClient.lastRenewal + 30*1000) < System.currentTimeMillis())
                                {
                                    holdingClients.remove(tokenValue);
                                    System.out.println("Renew Connection Token: " + Numeric.toHexString(thisClient.sessionToken));
                                    tokenValue = thisClient.generateNewSessionToken(secRand);
                                }
                                else if (thisClient.validated)
                                {
                                    System.out.println("Resend Validation: " + Numeric.toHexString(thisClient.sessionToken));
                                    sendToClient(thisClient, (byte)1, thisClient.sessionToken);
                                    break;
                                }
                                else
                                {
                                    System.out.println("Ignore renewal: " + Numeric.toHexString(thisClient.sessionToken));
                                    if (!thisClient.validated) sendToClient(thisClient, (byte)0, thisClient.sessionToken);
                                    break;
                                }
                            }

                            sendToClient(thisClient, (byte)0, thisClient.sessionToken);
                            holdingClients.put(tokenValue, thisClient);
                            System.out.println("New Connection Token: " + Numeric.toHexString(thisClient.sessionToken));
                            break;
                        case 1: //address
                            System.out.println("Connection From: " + Numeric.toHexString(rcvSessionToken));

                            thisClient = holdingClients.get(tokenValue);

                            //recover signature
                            if (thisClient != null && payload.length == 65 && !thisClient.validated)
                            {
                                Sign.SignatureData sigData = sigFromByteArray(payload);
                                //recover address from signature
                                BigInteger recoveredKey = Sign.signedMessageToKey(rcvSessionToken, sigData);
                                String recoveredAddr = "0x" + Keys.getAddress(recoveredKey);
                                UDPClientInstance newClient;
                                if (thisClient.ethAddress.length() == 0)
                                {
                                    newClient = new UDPClientInstance(address, port, recoveredAddr);
                                }
                                else if (recoveredAddr.equalsIgnoreCase(thisClient.ethAddress))
                                {
                                    System.out.println("Renew client.");
                                    newClient = thisClient;
                                }
                                else
                                {
                                    System.out.println("Reject.");
                                    break;
                                }

                                newClient.lastConnection = System.currentTimeMillis();
                                newClient.validated = true;
                                newClient.sessionToken = rcvSessionToken;
                                System.out.println("Validated: " + recoveredAddr);
                                purgeHoldingClients(address, port);
                                clients.put(recoveredAddr.toLowerCase(), newClient);
                                holdingClients.put(tokenValue, newClient);
                                sendToClient(newClient, (byte)1, newClient.sessionToken);
                                System.out.println("New Session T: " + Numeric.toHexString(newClient.sessionToken));
                            }
                            break;
                        case 2:
                            String payloadString = new String(payload);
                            System.out.println("RCV Message: " + Numeric.toHexString(rcvSessionToken));

                            thisClient = holdingClients.get(tokenValue);
                            if (thisClient != null)
                            {
                                thisClient = clients.get(thisClient.ethAddress);
                                if (thisClient != null)
                                {
                                    thisClient.setResponse(payloadString);
                                }
                            }
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
                catch (SignatureException e)
                {
                    e.printStackTrace();
                }
            }
        }

        //transmit back
        public void sendToClient(UDPClientInstance instance, byte type, byte[] stuffToSend) throws IOException
        {
            ByteArrayOutputStream bas          = new ByteArrayOutputStream();
            DataOutputStream      outputStream = new DataOutputStream(bas);

            int totalPacketLength = 2 + stuffToSend.length;
            outputStream.writeByte(type);
            outputStream.writeByte((byte)stuffToSend.length);
            outputStream.write(stuffToSend);
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

        public void reSendToClient(UDPClientInstance instance) throws IOException
        {
            if (instance != null && instance.currentQuery != null)
            {
                System.out.println("Re-Send to client: " + instance.packetId);
                DatagramPacket packet = new DatagramPacket(instance.currentQuery, instance.currentQuery.length, instance.IPAddress, instance.port);
                socket.send(packet);
            }
        }

        public UDPClientInstance sendToClient(String address, String method,
                                              MultiValueMap<String, String> argMap) throws IOException
        {
            UDPClientInstance instance = clients.get(address.toLowerCase());
            if (instance != null)
            {
                //send message
                ByteArrayOutputStream bas          = new ByteArrayOutputStream();
                DataOutputStream      outputStream = new DataOutputStream(bas);

                instance.packetId++;

                outputStream.writeByte(2);
                outputStream.writeByte(instance.packetId);
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

                instance.currentQuery = bas.toByteArray();
                instance.currentQuery[2] = (byte)payloadSize;

                DatagramPacket packet = new DatagramPacket(instance.currentQuery, instance.currentQuery.length, instance.IPAddress, instance.port);

                socket.send(packet);
            }

            return instance;
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

    private void purgeHoldingClients(InetAddress address, int port)
    {
        boolean removed = true;

        while (removed)
        {
            removed = removeMatchingClients(address, port);
        }
    }

    private boolean removeMatchingClients(InetAddress address, int port)
    {
        for (BigInteger token : holdingClients.keySet())
        {
            UDPClientInstance instance = holdingClients.get(token);
            if (instance.port == port && address.equals(instance.IPAddress))
            {
                holdingClients.remove(token);
                return true;
            }
        }

        return false;
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

}

