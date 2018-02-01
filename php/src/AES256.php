<?php
/**
 * AES.php
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */

namespace mervick\encryption;

/**
 * Class AES256
 * @package mervick\encryption
 */
class AES256
{
    /**
     * The output will be represent as json
     * @var string
     */
    const FORMAT_JSON = 'json';

    /**
     * The output will be represent as concatenated string
     * @var string
     */
    const FORMAT_CONCAT = 'concat';

    /**
     * Encrypt string
     *
     * @param string|numeric $input
     * @param string $passphrase
     * @param string $format [optional]
     * @return string
     * @throws \Exception
     */
    public static function encrypt($input, $passphrase, $format = self::FORMAT_CONCAT)
    {
        $input .= '';
        $salt = openssl_random_pseudo_bytes(8);
        $salted = $dx = '';
        while (strlen($salted) < 48) {
            $dx = md5($dx . $passphrase . $salt, true);
            $salted .= $dx;
        }
        $key = substr($salted, 0, 32);
        $iv = substr($salted, 32, 16);
        $encrypted_data = openssl_encrypt($input, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        $ct = base64_encode($encrypted_data);
        $iv = bin2hex($iv);
        $salt = bin2hex($salt);

        if ($format === self::FORMAT_JSON) {
            return json_encode(['ct' => $ct, 'iv' => $iv, 's' => $salt]);
        } elseif ($format === self::FORMAT_CONCAT) {
            return $salt . $iv . $ct;
        } else {
            throw new \Exception(sprintf('Unsupported format %s', $format));
        }
    }

    /**
     * Decrypt data from a CryptoJS json encoding string
     *
     * @param string $crypted
     * @param string $passphrase
     * @param string $format [optional] Default is concat
     * @return string|numeric
     * @throws \Exception
     */
    public static function decrypt($crypted, $passphrase, $format = self::FORMAT_CONCAT)
    {
        if ($format === self::FORMAT_JSON) {
            $jsonData = json_decode($crypted, true);
            if (!isset($jsonData['s']) || !isset($jsonData['iv']) || !isset($jsonData['ct'])) {
                return null;
            }
            try {
                $salt = hex2bin($jsonData['s']);
                $iv = hex2bin($jsonData['iv']);
                $ct = base64_decode($jsonData['ct']);
            } catch (Exception $e) {
                return null;
            }
        } elseif ($format === self::FORMAT_CONCAT) {
            $ct = base64_decode(substr($crypted, 48));
            $iv = hex2bin(substr($crypted, 16, 32));
            $salt = hex2bin(substr($crypted, 0, 16));
        } else {
            throw new \Exception(sprintf('Unsupported format %s', $format));
        }

        $concatenatedPassphrase = $passphrase . $salt;
        $md5 = [];
        $md5[0] = md5($concatenatedPassphrase, true);
        $result = $md5[0];
        for ($i = 1; $i < 3; $i++) {
            $md5[$i] = md5($md5[$i - 1] . $concatenatedPassphrase, true);
            $result .= $md5[$i];
        }
        $key = substr($result, 0, 32);
        return openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
    }
}
