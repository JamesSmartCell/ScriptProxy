package tapi.api.service.connection;

import org.springframework.util.MultiValueMap;
import org.web3j.utils.Numeric;
import tapi.api.service.TCPCallback;

import java.io.*;
import java.net.Socket;
import java.net.URLDecoder;

public class TCPClient extends Thread
{
    private final Socket socket;
    private long lastConnection;
    private volatile boolean running = false;
    private final TCPCallback serverCallback;
    private String address = "";
    private final int clientIndex;
    private byte[] challenge;
    private boolean isWaitingForResponse;

    private final static long CONNECTION_CLEANUP_TIME = 3L * 60L * 1000L; //after 5 minutes of silence remove a connection

    public TCPClient(Socket socket, TCPCallback callback, int index)
    {
        this.socket = socket;
        this.lastConnection = System.currentTimeMillis();
        this.serverCallback = callback;
        this.clientIndex = index;
        this.isWaitingForResponse = false;
    }

    @Override
    public void run()
    {
        running = true;

        while (running) {
            try {
                InputStream is = socket.getInputStream();
                int count = is.available();
                if (count > 0)
                {
                    byte[] rcv = new byte[count];
                    is.read(rcv, 0, count);

                    String rcvStr = Numeric.toHexString(rcv);
                    System.out.println("Receive Command: " + rcvStr.substring(0, 4));
                    isWaitingForResponse = false;
                    lastConnection = System.currentTimeMillis();
                    serverCallback.receivedMessage(clientIndex, rcv);
                }

                sleep(10);
            }
            catch (Exception e)
            {
                //
                running = false;
            }
        };

        serverCallback.disconnect(clientIndex);
    }

    public boolean hasTimedOut()
    {
        return (System.currentTimeMillis() - lastConnection) > CONNECTION_CLEANUP_TIME;
    }

    public void setChallenge(byte[] challenge) {
        this.challenge = challenge;
    }

    public void setAddress(String address)
    {
        this.address = address;
    }

    public String getAddress()
    {
        return address;
    }

    public byte[] getChallenge()
    {
        return challenge;
    }

    public void sendKeepAlive()
    {
        try
        {
            socket.setTcpNoDelay(true);
            OutputStream output = socket.getOutputStream();
            byte[] msg = new byte[challenge.length + 1];
            msg[0] = 0x06;
            System.arraycopy(challenge, 0, msg, 1, challenge.length);
            output.write(msg);
            output.flush();
        }
        catch (Exception e)
        {
            //
        }
    }

    public void sendChallenge()
    {
        try
        {
            socket.setTcpNoDelay(true);
            OutputStream output = socket.getOutputStream();
            byte[] msg = new byte[challenge.length + 1];
            msg[0] = 0x02;
            System.arraycopy(challenge, 0, msg, 1, challenge.length);
            output.write(msg);
            output.flush();
        }
        catch (Exception e)
        {
            //
        }
    }

    public void terminate() {
        try
        {
            socket.setTcpNoDelay(true);
            OutputStream output = socket.getOutputStream();
            output.flush();
            output.close();
        }
        catch (Exception e)
        {
            //
        }

        running = false;
    }

    public void sendMessage(String method, MultiValueMap<String, String> argMap)
    {
        try
        {
            if (isWaitingForResponse) return;
            isWaitingForResponse = true;

            //send message
            ByteArrayOutputStream bas          = new ByteArrayOutputStream();
            DataOutputStream outputStream = new DataOutputStream(bas);

            System.out.println("Create API call: " + method);

            outputStream.writeByte(0x04);

            writeValue(outputStream, method);

            for (String key : argMap.keySet())
            {
                writeValue(outputStream, key);
                String param = "";
                if (argMap.get(key).size() > 0)
                {
                    param = URLDecoder.decode(argMap.get(key).get(0), "UTF-8");
                }
                writeValue(outputStream, param);
            }

            outputStream.flush();
            outputStream.close();

            socket.setTcpNoDelay(true);
            OutputStream output = socket.getOutputStream();
            output.write(bas.toByteArray());
            output.flush();
        }
        catch (Exception e)
        {
            //
        }
    }

    private int writeValue(DataOutputStream outputStream, String value) throws IOException
    {
        int writeLength = writeLengthHeader(outputStream, value);
        outputStream.write(value.getBytes());
        writeLength += value.length();
        return writeLength;
    }

    private int writeLengthHeader(DataOutputStream outputStream, String value) throws IOException
    {
        int writtenLength = 0;
        int length = value.length();

        while (length >= 0)
        {
            int lengthToWrite = length < 0xFF ? length : 0xFF;
            outputStream.writeByte((byte)lengthToWrite);
            length -= 0xFF;
            writtenLength++;
        }

        return writtenLength;
    }
}
