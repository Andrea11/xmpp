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

namespace Fabiang\Xmpp\EventListener\Stream;

use Fabiang\Xmpp\Event\XMLEvent;
use Fabiang\Xmpp\Connection\Test;
use Fabiang\Xmpp\Options;

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-01-11 at 18:20:16.
 */
class StreamTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @var Stream
     */
    protected $object;

    /**
     *
     * @var Test
     */
    protected $connection;

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     *
     * @return void
     */
    protected function setUp()
    {
        $this->object     = new Stream;
        $this->connection = new Test;
        $options          = new Options;
        $options->setConnection($this->connection);
        $this->object->setOptions($options);
        $this->connection->setReady(true);
    }

    /**
     * Test what event are attached.
     *
     * @covers Fabiang\Xmpp\EventListener\Stream\Stream::attachEvents
     * @return void
     */
    public function testAttachEvents()
    {
        $this->object->attachEvents();

        $output = $this->connection->getOutputStream()->getEventManager();
        $input  = $this->connection->getInputStream()->getEventManager();
        $this->assertArrayHasKey('{http://etherx.jabber.org/streams}stream', $output->getEventList());
        $this->assertArrayHasKey('{http://etherx.jabber.org/streams}features', $input->getEventList());
    }

    /**
     * Test starting client stream.
     *
     * @covers Fabiang\Xmpp\EventListener\Stream\Stream::stream
     * @covers Fabiang\Xmpp\EventListener\Stream\Stream::streamServer
     * @covers Fabiang\Xmpp\EventListener\Stream\Stream::features
     * @covers Fabiang\Xmpp\EventListener\Stream\Stream::isBlocking
     * @return void
     */
    public function testEvents()
    {
        $element = new \DOMElement('machanism', 'PLAIN');
        $event   = new XMLEvent;
        $event->setParameters(array($element));
        $this->connection->setReady(false);

        $this->assertFalse($this->object->isBlocking());
        $event->setStartTag(true);
        $this->object->stream($event);
        $this->assertTrue($this->object->isBlocking());

        $event->setStartTag(false);
        $this->object->streamServer($event);
        $this->assertFalse($this->object->isBlocking());

        $event->setStartTag(true);
        $this->object->stream($event);
        $event->setStartTag(false);
        $this->object->features();
        $this->assertFalse($this->object->isBlocking());
        $this->assertTrue($this->connection->isReady());
    }

}
