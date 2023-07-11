package com.stl.smartlayer.service;

import com.stl.smartlayer.service.connection.TCPClient;
import io.reactivex.Observable;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static com.stl.smartlayer.APIController.IOT_PORT;

@Service
public class ASyncTCPService extends Thread implements TCPCallback
{
    private final Map<String, Integer> clientMap = new ConcurrentHashMap<>();
    private final Map<Integer, TCPClient> clientIndexList = new ConcurrentHashMap<>();
    private final Map<Integer, List<String>> clientResponse = new ConcurrentHashMap<>();
    private final ExecutorService es = Executors.newCachedThreadPool();
    private final SecureRandom secRand = new SecureRandom();
    private int clientIndex = 0;

    public ASyncTCPService()
    {
        start();
    }

    @Override
    public void run()
    {

        Observable.interval(1, 2, TimeUnit.MINUTES)
                .doOnNext(l -> sendKeepAlive()).subscribe();

        try (ServerSocket serverSocket = new ServerSocket(IOT_PORT))
        {
            System.out.println("TCP server listening on port " + IOT_PORT);

            while (true)
            {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected: #" + clientIndex);

                TCPClient client = new TCPClient(socket, this, clientIndex);
                clientIndexList.put(clientIndex, client);
                clientIndex++;
                es.submit(client::start);
            }

        } catch (IOException ex) {
            System.out.println("Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void sendKeepAlive()
    {
        List<String> removalAddrs = new ArrayList<>();

        for (int index : clientIndexList.keySet())
        {
            TCPClient client = clientIndexList.get(index);
            if (!client.isAlive() || client.hasTimedOut())
            {
                client.terminate();
            }
            else
            {
                client.sendKeepAlive();
            }
        }

        for (String address : clientMap.keySet())
        {
            int index = clientMap.get(address);
            if (!clientIndexList.containsKey(index)) removalAddrs.add(address);
        }

        //finally remove the orphaned address to client pointers
        for (String rmAddr : removalAddrs)
        {
            System.out.println("REMOVE orphaned client: " + rmAddr);
            clientMap.remove(rmAddr);
        }
    }

    @Override
    public void receivedMessage(int index, byte[] bytes) {
        TCPClient client;

        byte opcode = bytes[0];
        byte[] message = Arrays.copyOfRange(bytes, 1, bytes.length);
        String address;
        List<String> responseList;
        switch (opcode)
        {
            case 0x01: //login
                address = Numeric.toHexString(message);
                client = clientIndexList.get(index);
                System.out.println("RCV: Login: " + address);
                client.setChallenge(createChallenge());
                client.sendChallenge();
                //create challenge and send
                break;
            case 0x02: //challenge - client
                break;
            case 0x03: //challenge response, address + sig (sign personal)
            case 0x07: //               "        "         (normal sign)
                client = clientIndexList.get(index);
                byte[] addrBytes = Arrays.copyOfRange(message, 0, 20);
                byte[] sig = Arrays.copyOfRange(message, 20, message.length);
                System.out.println("ADDR: " + Numeric.toHexString(addrBytes) + " : " + Numeric.toHexString(sig));
                if (client == null || addrBytes.length != 20 || sig.length != 65) break;
                byte[] msg = client.getChallenge();
                System.out.println("MSG: " + Numeric.toHexString(msg));
                byte[] msgHash = (opcode == 0x03)? getEthereumMessageHash(msg) : Hash.sha3(msg);
                String recoveredAddr = recoverAddressFromSignature(msgHash, sig);
                //final check
                if (Numeric.toHexString(addrBytes).equalsIgnoreCase(recoveredAddr)) {
                    client.setAddress(recoveredAddr);
                    addToClientMap(recoveredAddr, index);
                }
                else {
                    client.terminate();
                }
                break;
            case 0x04: //message to client device
                break;
            case 0x08: //response
            case 0x05: //response from client device
                responseList = clientResponse.computeIfAbsent(index, k -> new ArrayList<>());
                responseList.add(new String(message, StandardCharsets.UTF_8));
                break;
            case 0x06: //device keepalive
                break;
        }
    }

    private void addToClientMap(String recoveredAddr, int index)
    {
        //check for old connections for this address
        for (int clIndex : clientIndexList.keySet())
        {
            if (clIndex == index) continue;
            TCPClient client = clientIndexList.get(clIndex);

            if (client.getAddress().equalsIgnoreCase(recoveredAddr))
            {
                System.out.println("Terminating Index: " + clIndex + " (" + recoveredAddr + ")");
                client.terminate();
            }
        }

        System.out.println("Link Address: " + recoveredAddr + " Client Index: " + index);
        //Link client to address
        clientMap.put(recoveredAddr, index);
    }

    private byte[] createChallenge()
    {
        byte[] randBytes = new byte[16];
        secRand.nextBytes(randBytes);
        return randBytes;
    }

    @Override
    public void disconnect(int index) {
        TCPClient client = clientIndexList.get(index);
        if (client != null) {
            System.out.println("Disconnect: #" + index);
            clientIndexList.remove(index);
        }
    }

    public CompletableFuture<String> getResponse(String address, String method,
                                                 MultiValueMap<String, String> argMap, String origin) throws InterruptedException, IOException
    {
        if (!clientMap.containsKey(address)) return CompletableFuture.completedFuture("No device found");
        final int clientIndex = clientMap.get(address);
        TCPClient client = clientIndexList.get(clientIndex);
        if (client == null)
        {
            return CompletableFuture.completedFuture("No device found");
        }
        else
        {
            List<String> responseList = clientResponse.get(clientIndex);
            if (responseList != null) responseList.clear();
        }

        //is there an identical call in progress from the same client?
        client.sendMessage(method, argMap);
        //now wait for a response (TODO use semaphore & add timeout)
        while (true)
        {
            Thread.sleep(100);

            List<String> responseList = clientResponse.get(clientIndex);
            if (responseList != null && responseList.size() > 0)
            {
                //pull response and return
                return CompletableFuture.completedFuture(responseList.get(0));
            }
        }
    }


    //Signing Code
    private String recoverAddressFromSignature(byte[] hashedMessage, byte[] signatureBytes)
    {
        String recoveredAddr = "";
        try
        {
            Sign.SignatureData sigData = sigFromByteArray(signatureBytes);
            BigInteger recoveredKey  = Sign.signedMessageHashToKey(hashedMessage, sigData);
            recoveredAddr = "0x" + Keys.getAddress(recoveredKey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return recoveredAddr;
    }

    private static Sign.SignatureData sigFromByteArray(byte[] sig)
    {
        if (sig.length < 64 || sig.length > 65) return null;

        byte   subv = sig[64];
        if (subv < 27) subv += 27;

        byte[] subrRev = Arrays.copyOfRange(sig, 0, 32);
        byte[] subsRev = Arrays.copyOfRange(sig, 32, 64);
        return new Sign.SignatureData(subv, subrRev, subsRev);
    }

    static final String MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

    static byte[] getEthereumMessagePrefix(int messageLength) {
        return MESSAGE_PREFIX.concat(String.valueOf(messageLength)).getBytes();
    }

    static byte[] getEthereumMessageHash(byte[] message) {
        byte[] prefix = getEthereumMessagePrefix(message.length);

        byte[] result = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(message, 0, result, prefix.length, message.length);

        return Hash.sha3(result);
    }

    public CompletableFuture<String> getDeviceAddress(String ipAddress) throws UnknownHostException
    {
        InetAddress inetAddress  = InetAddress.getByName(ipAddress);
        StringBuilder sb = new StringBuilder();
        sb.append("Devices found on IP address: ");
        sb.append(ipAddress);
        byte[]       filter;
        boolean foundAddr = false;

        for (String address : clientMap.keySet())
        {
            foundAddr = true;
            sb.append("</br>");
            sb.append(address);
        }

        if (!foundAddr)
        {
            sb.append("</br>No devices");
        }

        return CompletableFuture.completedFuture(sb.toString());
    }
}
