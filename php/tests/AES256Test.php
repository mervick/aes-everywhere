<?php
/**
 * AES256Test.php
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */

namespace mervick\aesEverywhere\tests;

use mervick\aesEverywhere\AES256;
use PHPUnit\Framework\TestCase;


define('FAIL', 'Invalid decryption');

/**
 * Class AES256Test
 * @package mervick\aesEverywhere\tests
 */
class AES256Test extends TestCase
{
    public function test_decrypt1()
    {
        $text = AES256::decrypt("U2FsdGVkX1+Z9xSlpZGuO2zo51XUtsCGZPs8bKQ/jYg=", "pass");
        $this->assertEquals($text, "test", FAIL);
    }

    public function test_decrypt2()
    {
        $text = AES256::decrypt("U2FsdGVkX1+8b3WpGTbZHtd2T9PNQ+N7GqebGaOV3cI=", "Data 😄 текст");
        $this->assertEquals($text, "test", FAIL);
    }

    public function test_decrypt3()
    {
        $text = AES256::decrypt("U2FsdGVkX18Kp+T3M9VajicIO9WGQQuAlMscLGiTnVyHRj2jHObWshzJXQ6RpJtW", "pass");
        $this->assertEquals($text, "Data 😄 текст", FAIL);
    }

    public function test_encrypt_decrypt1()
    {
        $text = "Test! @#$%^&*";
        $passw = "pass";
        $enc = AES256::encrypt($text, $passw);
        $dec = AES256::decrypt($enc, $passw);
        $this->assertEquals($text, $dec, FAIL);
    }

    public function test_encrypt_decrypt2()
    {
        $text = "Test! @#$%^&*( 😆😵🤡👌 哈罗 こんにちわ Акїў 😺";
        $passw = "pass";
        $enc = AES256::encrypt($text, $passw);
        $dec = AES256::decrypt($enc, $passw);
        $this->assertEquals($text, $dec, FAIL);
    }

    public function test_encrypt_decrypt3()
    {
        $text = "Test! @#$%^&*( 😆😵🤡👌 哈罗 こんにちわ Акїў 😺";
        $passw = "哈罗 こんにちわ Акїў 😺";
        $enc = AES256::encrypt($text, $passw);
        $dec = AES256::decrypt($enc, $passw);
        $this->assertEquals($text, $dec, FAIL);
    }
}
