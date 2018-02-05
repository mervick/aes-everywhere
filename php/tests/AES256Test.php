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


/**
 * Class AES256Test
 * @package mervick\aesEverywhere\tests
 */
class AES256Test extends TestCase
{
    /**
     * Test AES256
     * @throws \Exception
     */
    public function testAES256()
    {
        $passphrases = require __DIR__ . '/data/passphrases.php';
        $data = require __DIR__ . '/data/data.php';
        $encryptedArray = json_decode(file_get_contents(__DIR__ . '/data/encrypted.json'), true);

        $this->assertNotEmpty($data, 'data.raw can\'t be empty');
        $this->assertNotEmpty($passphrases, 'passphrases can\'t be empty');

        $sprintfStr = 'with combination of data key "%s", passphrase key "%s", format "%s"';
        $last = null;

        foreach ($data as $dataKey => $original) {
            foreach ($passphrases as $passKey => $passphrase) {
                foreach ([AES256::FORMAT_JSON, AES256::FORMAT_CONCAT] as $format) {
                    $encrypted = AES256::encrypt($original, $passphrase, $format);

                    $this->assertArrayHasKey($format, $encryptedArray);
                    $this->assertArrayHasKey($dataKey, $encryptedArray[$format]);
                    $this->assertArrayHasKey($passKey, $encryptedArray[$format][$dataKey]);

                    $this->assertTrue($original == AES256::decrypt($encryptedArray[$format][$dataKey][$passKey], $passphrase, $format),
                        sprintf("Can't decrypt data $sprintfStr from encrypted.json", $dataKey, $passKey, $format));

                    if (!empty($original)) {
                        $this->assertNotEmpty($encrypted,
                            sprintf("Encrypted data $sprintfStr can't be empty", $dataKey, $passKey, $format));
                    }
                    $this->assertNotEquals($encrypted, $original,
                        sprintf("Encrypted data $sprintfStr can't be equal with input string", $dataKey, $passKey, $format));

                    if ($format === AES256::FORMAT_JSON) {
                        $this->assertJson($encrypted,
                            sprintf("Encrypted data must be valid json string $sprintfStr", $dataKey, $passKey, $format));

                        $array = json_decode($encrypted, true);

                        $this->assertArrayHasKey('s', $array, // salt
                            sprintf("The json of encrypted data must contain 's' key $sprintfStr", $dataKey, $passKey, $format));
                        $this->assertArrayHasKey('iv', $array, // IV
                            sprintf("The json of encrypted data must contain 'iv' key $sprintfStr", $dataKey, $passKey, $format));
                        $this->assertArrayHasKey('ct', $array, // encoded string
                            sprintf("The json of encrypted data must contain 'ct' key $sprintfStr", $dataKey, $passKey, $format));
                    }

                    $decrypted = AES256::decrypt($encrypted, $passphrase, $format);

                    $this->assertTrue($decrypted == $original,
                        sprintf("Decrypted code not equal to original $sprintfStr", $dataKey, $passKey, $format));
                }
            }
        }
    }
}
