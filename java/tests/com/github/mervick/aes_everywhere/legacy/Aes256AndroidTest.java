package com.github.mervick.aes_everywhere.legacy;

import com.github.mervick.aes_everywhere.Aes256Test;


public class Aes256AndroidTest extends Aes256Test
{
    protected byte[] encrypt(byte[] in, byte[] pass) throws Exception {
        return Aes256.encrypt(in, pass);
    }

    protected String encrypt(String in, String pass) throws Exception {
        return Aes256.encrypt(in, pass);
    }

    protected byte[] decrypt(byte[] in, byte[] pass) throws Exception {
        return Aes256.decrypt(in, pass);
    }

    protected String decrypt(String in, String pass) throws Exception {
        return Aes256.decrypt(in, pass);
    }
}
