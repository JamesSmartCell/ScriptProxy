package com.stl.smartlayer.service;

public interface TCPCallback
{
    void receivedMessage(int index, byte[] bytes);
    void disconnect(int index);
}
