<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('libs/autoload.php');
require_once('abconstants.php');


use Monolog\Processor\WebProcessor;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Formatter\LineFormatter;
use Monolog\Formatter\NormalizerFormatter;

class PhpOidcLogger
{

    /**
     * Monolog instance to hold and use
     * @var Monolog\Logger
     */
    static protected $logInstance;


    /**
     * Monolog instance to hold and use
     * @var Monolog\Logger
     */
    static protected $logWebInstance;


    /**
     * Method to return the Monolog instance
     *
     * @return Monolog\Logger
     */
    static public function getInstance()
    {
        if (! self::$logInstance) {
            self::configureInstance(LOGFILE, LOGLEVEL);
        }

        return self::$logInstance;
    }

    /**
     * Method to return the Monolog instance with Web Processing
     *
     * @return Monolog\Logger
     */
    static public function getWebInstance()
    {
        if (! self::$logWebInstance) {
            self::configureWebInstance(LOGFILE, LOGLEVEL);
        }

        return self::$logWebInstance;
    }

    /**
     * Configures the log instance
     * @param $logFile  String Log file path
     * @param $logLevel String Log level
     */
    static protected function configureInstance($logFile, $logLevel)
    {
        self::$logInstance = new Logger('oidcoplogger');
        $levels = array(
            'DEBUG' => Logger::DEBUG,
            'INFO' => Logger::INFO,
            'NOTICE' => Logger::NOTICE,
            'WARNING' => Logger::WARNING,
            'ERROR' => Logger::ERROR,
            'CRITICAL' => Logger::CRITICAL,
            'ALERT' => Logger::ALERT,
            'EMERGENCY' => Logger::EMERGENCY
        );
        $logLevel = $levels[$logLevel];

//        $dateFormat = "Y n j, g:i a";
        $dateFormat = "m-d G:i:s ";
        // the default output format is "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n"
        $output = "%datetime% %level_name% %message%\n\n";
        // finally, create a formatter
        $formatter = new LineFormatter($output, $dateFormat);
//        $formatter = new NormalizerFormatter($dateFormat);

        // Create a handler
        $stream = new StreamHandler($logFile, $logLevel);
        $stream->setFormatter($formatter);

//        $stream = new \Monolog\Handler\SyslogHandler($logFile, $logLevel);
//        $stream->setFormatter($formatter);
        self::$logInstance->pushHandler($stream);
    }

    /**
     * Configures the log instance
     * @param $logFile  String Log file path
     * @param $logLevel String Log level
     */
    static protected function configureWebInstance($logFile, $logLevel)
    {
        self::$logWebInstance = new Logger('oidcoplogger');
        $levels = array(
            'DEBUG' => Logger::DEBUG,
            'INFO' => Logger::INFO,
            'NOTICE' => Logger::NOTICE,
            'WARNING' => Logger::WARNING,
            'ERROR' => Logger::ERROR,
            'CRITICAL' => Logger::CRITICAL,
            'ALERT' => Logger::ALERT,
            'EMERGENCY' => Logger::EMERGENCY
        );
        $logLevel = $levels[$logLevel];

//        $dateFormat = "Y n j, g:i a";
        $dateFormat = "m-d G:i:s ";
        // the default output format is "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n"
        $output = "==============================================================================\n%datetime% %level_name% %message% \n%extra% %context%\n----------------------------------------------------------\n\n";
        // finally, create a formatter
        $formatter = new LineFormatter($output, $dateFormat);
//        $formatter = new NormalizerFormatter($dateFormat);

        // Create a handler
        $stream = new StreamHandler($logFile, $logLevel);
        $stream->setFormatter($formatter);
        self::$logWebInstance->pushHandler($stream);
        self::$logWebInstance->pushProcessor(new WebProcessor());
    }

}

function log_debug($format, $args = null)
{
    PhpOidcLogger::getInstance()->addDebug(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_info($format, $args = null)
{
    PhpOidcLogger::getInstance()->addInfo(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_notice($format, $args = null)
{
    PhpOidcLogger::getInstance()->addNotice(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_warning($format, $args = null)
{
    PhpOidcLogger::getInstance()->addWarning(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_error($format, $args = null)
{
    PhpOidcLogger::getInstance()->addError(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_critical($format, $args = null)
{
    PhpOidcLogger::getInstance()->addCritical(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_alert($format, $args = null)
{
    PhpOidcLogger::getInstance()->addAlert(vsprintf($format, array_slice(func_get_args(), 1)));
}

function log_emergency($format, $args = null)
{
    PhpOidcLogger::getInstance()->addEmergency(vsprintf($format, array_slice(func_get_args(), 1)));
}



function logw_debug($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addDebug(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_info($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addInfo(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_notice($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addNotice(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_warning($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addWarning(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_error($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addError(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_critical($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addCritical(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_alert($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addAlert(vsprintf($format, array_slice(func_get_args(), 1)));
}

function logw_emergency($format, $args = null)
{
    PhpOidcLogger::getWebInstance()->addEmergency(vsprintf($format, array_slice(func_get_args(), 1)));
}

