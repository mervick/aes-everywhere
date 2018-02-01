<?php
/**
 * AES256Test.php
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */

require __DIR__ . '/../../vendor/autoload.php';

$composer = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);
if (!isset($composer['autoload']['psr-4']) || !is_array($composer['autoload']['psr-4'])) {
    throw new \Exception('Unable to get autoload.psr-4 from composer.json');
}

$classLoader = new \Composer\Autoload\ClassLoader();
foreach ($composer['autoload']['psr-4'] as $ns => $dir) {
    $classLoader->addPsr4($ns, __DIR__ . '/../../' . $dir, true);
}
$classLoader->register();
