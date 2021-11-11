package tapi.api.service;

public interface TCPCallback
{
    void receivedMessage(int index, byte[] bytes);
    void disconnect(int index);
}
