<?php

/**
 * Copyright 2014 Fabian Grutschus. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the copyright holders.
 *
 * @author    Fabian Grutschus <f.grutschus@lubyte.de>
 * @copyright 2014 Fabian Grutschus. All rights reserved.
 * @license   BSD
 * @link      http://github.com/fabiang/xmpp
 */

namespace Fabiang\Xmpp\EventListener\Stream\Authentication;

use Fabiang\Xmpp\EventListener\AbstractEventListener;
use Fabiang\Xmpp\Event\XMLEvent;
use Fabiang\Xmpp\Util\XML;
use Fabiang\Xmpp\Exception\Stream\AuthenticationErrorException;

/**
 * Handler for "digest md5" authentication mechanism.
 *
 * @package Xmpp\EventListener\Authentication
 */
class ScramSha1 extends AbstractEventListener implements AuthenticationInterface
{

    /**
     * Is event blocking stream.
     *
     * @var boolean
     */
    protected $blocking = false;

    /**
     *
     * @var string
     */
    protected $username;

    /**
     *
     * @var string
     */
    protected $password;

    /**
     *
     * @var string
     */
    protected $authenticate;

    /**
     *
     * @var string
     */
    protected $challenge;

    /**
     *
     * @var string
     */
    protected $success;

    /**
     * {@inheritDoc}
     */
    public function attachEvents()
    {
        $input = $this->getInputEventManager();
        $input->attach('{urn:ietf:params:xml:ns:xmpp-sasl}challenge', array($this, 'challenge'));
        $input->attach('{urn:ietf:params:xml:ns:xmpp-sasl}success', array($this, 'success'));

        $output = $this->getOutputEventManager();
        $output->attach('{urn:ietf:params:xml:ns:xmpp-sasl}auth', array($this, 'auth'));
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate($username, $password)
    {
        $this->setUsername($username)->setPassword($password);
        $cNonce = $this->getCnonce();
        $initialMessage = 'n='.$username.',r='.$cNonce;
        $g2s_header = 'n,,';
        $auth = '<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="SCRAM-SHA-1">';
        $auth .= XML::base64Encode($g2s_header.$initialMessage);
        $auth .= '</auth>';

        $this->authenticate = ['InitialMessage' => $initialMessage, 'ClientNonce' => $cNonce];
        $this->getConnection()->send($auth);
    }

    /**
     * Authentication starts -> blocking.
     *
     * @return void
     */
    public function auth()
    {
        $this->blocking = true;
    }

    /**
     * Challenge string received.
     *
     * @param XMLEvent $event XML event
     * @return void
     */
    public function challenge(XMLEvent $event)
    {
        if ($event->isEndTag()) {
            list($element) = $event->getParameters();

            $challenge = XML::base64Decode($element->nodeValue);

            $values    = $this->parseChallenge($challenge);

            $cNonce= substr($values['ServerNonce'], 0, strlen($this->authenticate['ClientNonce']));

            if ( $cNonce <> $this->authenticate['ClientNonce'])
            {
                throw new AuthenticationErrorException("Error when receiving challenge: \"$challenge\"");
            }

            if (!isset($values['ServerNonce']) || !isset($values['Salt']) || !isset($values['Iterations'])) {
                throw new AuthenticationErrorException("Error when receiving challenge: \"$challenge\"");
            }
            $this->challenge = ['Challenge' => $challenge];

            $send = '<response xmlns="urn:ietf:params:xml:ns:xmpp-sasl">'. $this->response($values) . '</response>';

            $this->challenge['AuthMessage'] = $values['AuthMessage'];
            $this->challenge['SaltedPassword'] = $values['SaltedPassword'];
            
            $this->getConnection()->send($send);
        }
    }

    /**
     * Parse challenge string and return its values as array.
     *
     * @param string $challenge
     * @return array
     */
    protected function parseChallenge($challenge)
    {
        if (!$challenge) {
            return array();
        }

        preg_match("#^r=([\x21-\x2B\x2D-\x7E]+),s=((?:[A-Za-z0-9/+]{4})*(?:[A-Za-z0-9]{3}=|[A-Xa-z0-9]{2}==)?),i=([0-9]*)(,[A-Za-z]=[^,])*$#", $challenge, $matches);

        list(,$sNonce, $salt, $i) = $matches;

        $matches = ['ServerNonce' => $sNonce, 'Salt' => XML::base64Decode($salt), 'Iterations' => $i];

        return $matches;
    }

    /**
     * Generate response data.
     *
     * @param array $values
     */
    protected function response(&$values)
    {
        $clientFinalMessageBare = 'c=biws,r='.$values['ServerNonce'];
        $saltedPassword = hash_pbkdf2('sha1', $this->password, $values['Salt'], $values['Iterations'], 0, TRUE);        
        $clientKey = hash_hmac('sha1', 'Client Key', $saltedPassword, TRUE);
        $storedKey = sha1($clientKey, TRUE);
        $authMessage = $this->authenticate['InitialMessage'].','.$this->challenge['Challenge'].','.$clientFinalMessageBare;
        $clientSignature = hash_hmac('sha1', $authMessage, $storedKey, TRUE);
        $clientProof = $clientKey ^ $clientSignature;

        $response = $clientFinalMessageBare.',p='.XML::base64Encode($clientProof);

        $values['AuthMessage'] = $authMessage;
        $values['SaltedPassword'] = $saltedPassword;


        return XML::base64Encode($response);
    }


    /**
    * Creates the client nonce for the response
    *
    * @return string  The cnonce value
    */
    protected function getCnonce()
    {
        $str = '';
        for ($i=0; $i<32; $i++) {
            $str .= chr(mt_rand(0, 255));
        }

        return XML::base64Encode($str);

    }

    /**
     * Handle success event.
     *
     * @return void
     */
    public function success(XMLEvent $event)
    {
        if ($event->isEndTag()) {
            list($element) = $event->getParameters();

            $response = XML::base64Decode($element->nodeValue);
            $value    = $this->parseResponse($response);
            $value    = XML::base64Decode($value);

            $serverKey = hash_hmac('sha1', 'Server Key', $this->challenge['SaltedPassword'], TRUE);
            $serverSignature = hash_hmac('sha1', $this->challenge['AuthMessage'], $serverKey, TRUE);

            if ($value !== $serverSignature) {
                throw new AuthenticationErrorException("Error pending server signature verification");
            }

            $this->blocking = false;
        }
    }

    /**
     * Parse challenge string and return its values as array.
     *
     * @param string $challenge
     * @return array
     */
    protected function parseResponse($response)
    {
        if (!$response) {
            return array();
        }

        preg_match('#^v=((?:[A-Za-z0-9/+]{4})*(?:[A-Za-z0-9]{3}=|[A-Xa-z0-9]{2}==)?)$#', $response, $match);

        return $match[1];
    }

    /**
     * {@inheritDoc}
     */
    public function isBlocking()
    {
        return $this->blocking;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function setUsername($username)
    {
        $this->username = $username;
        return $this;
    }

    public function getPassword()
    {
        return $this->password;
    }

    public function setPassword($password)
    {
        $this->password = $password;
        return $this;
    }
}
