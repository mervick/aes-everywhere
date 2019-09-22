package com.github.mervick.aes_everywhere;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static java.nio.charset.StandardCharsets.UTF_8;


public class Aes256Test
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

    private void testDecrypt(String in, String pass, String expect) {
        String result = "";
        byte[] bytes = new byte[0];

        try {
            result = decrypt(in, pass);
        } catch (Exception e) { }

        try {
            bytes = decrypt(in.getBytes(UTF_8), pass.getBytes(UTF_8));
        } catch (Exception e) { }

        assertEquals(expect, result, "Fail strings");
        assertArrayEquals(expect.getBytes(UTF_8), bytes, "Fail bytes");
    }

    @Test
    public void testDecrypt1() throws Exception {
        testDecrypt("U2FsdGVkX1+Z9xSlpZGuO2zo51XUtsCGZPs8bKQ/jYg=", "pass", "test");
    }

    @Test
    public void testDecrypt2() {
        testDecrypt("U2FsdGVkX1+8b3WpGTbZHtd2T9PNQ+N7GqebGaOV3cI=", "Data 😄 текст", "test");
    }

    @Test
    public void testDecrypt3() {
        testDecrypt("U2FsdGVkX18Kp+T3M9VajicIO9WGQQuAlMscLGiTnVyHRj2jHObWshzJXQ6RpJtW", "pass", "Data 😄 текст");
    }

    private void testEncryptDecrypt(String in, String pass) {
        String result = "";
        byte[] bytes = new byte[0];

        try {
            result = decrypt(encrypt(in, pass), pass);
        } catch (Exception e) { }

        try {
            bytes = decrypt(encrypt(in.getBytes(UTF_8), pass.getBytes(UTF_8)), pass.getBytes(UTF_8));
        } catch (Exception e) { }

        assertEquals(in, result, "Fail strings");
        assertArrayEquals(in.getBytes(UTF_8), bytes, "Fail bytes");
    }

    @Test
    public void testEncryptDecrypt1() {
        testEncryptDecrypt("Test! @#$%^&*", "pass");
    }

    @Test
    public void testEncryptDecrypt2() {
        testEncryptDecrypt("Test! @#$%^&*( 😆😵🤡👌 哈罗 こんにちわ Акїў 😺", "pass");
    }

    @Test
    public void testEncryptDecrypt3() {
        testEncryptDecrypt("Test! @#$%^&*( 😆😵🤡👌 哈罗 こんにちわ Акїў 😺", "哈罗 こんにちわ Акїў 😺");
    }
}
