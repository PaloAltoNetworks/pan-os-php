<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


class Threat
{
    use ReferenceableObject;
    use PathableName;

    public $type = 'tmp';

    public $threatname = null;
    public $category = null;
    public $severity = null;
    public $engine_version = null;
    public $default_action = 'allow';

    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
        $this->xmlroot = null;
    }

    public function load_from_domxml( $threatx )
    {
        $tmp = DH::findFirstElement('threatname', $threatx);
        if( $tmp !== FALSE )
            $this->threatname = $tmp->textContent;

        $tmp = DH::findFirstElement('category', $threatx);
        if( $tmp !== FALSE )
        {
            //'filter=!(category eq browser-hijack) and !(category eq adware) and !(category eq spyware) and !(category eq backdoor) and !(category eq data-theft) and !(category eq keylogger) and !(category eq webshell) and !(category eq botnet) and !(category eq net-worm) and !(category eq command-and-control) and !(category eq phishing-kit) and !(category eq cryptominer) and !(category eq downloader) and !(category eq hacktool) and !(category eq tls-fingerprint) and !(category eq fraud) and !(category eq info-leak) and !(category eq post-exploitation) and !(category eq phishing) and !(category eq code-execution) and !(category eq overflow) and !(category eq dos) and !(category eq brute-force) and !(category eq sql-injection) and !(category eq insecure-credentials) and !(category eq protocol-anomaly) and !(category eq code-obfuscation) and !(category eq exploit-kit)'
            /*
            * browser-hijack
             * adware
             *
             * spyware
             * backdoor
             * data-theft
             * keylogger
             * webshell
             * botnet
             * net-worm
             * command-and-control
             * phishing-kit
             * cryptominer
             * downloader
             * hacktool
             * tls-fingerprint
             * fraud
             * info-leak
             * post-exploitation
             * phishing
             * code-execution
             * overflow
             * dos
             * brute-force
             * sql-injection
             * insecure-credentials
             * protocol-anomaly
             * code-obfuscation
             * exploit-kit
            */
            $this->category = $tmp->textContent;
        }


        $tmp = DH::findFirstElement('severity', $threatx);
        if( $tmp !== FALSE )
        {
            /*
             * informational
             * low
             * medium
             * high
             * critical
             */
            $this->severity = $tmp->textContent;
        }


        $tmp = DH::findFirstElement('engine-version', $threatx);
        if( $tmp !== FALSE )
            $this->engine_version = $tmp->textContent;

        $tmp = DH::findFirstElement('default-action', $threatx);
        if( $tmp !== FALSE )
        {
            /* possible values
           allow
           alert
           reset-both
           reset-client
           reset-server
           drop-all-packets
            */
            $this->default_action = $tmp->textContent;
        }

    }

    public function type()
    {
        return $this->type;
    }

    public function name()
    {
        return $this->name;
    }

    public function threatname()
    {
        return $this->threatname;
    }

    public function severity()
    {
        return $this->severity;
    }

    public function defaultAction()
    {
        return $this->default_action;
    }

    public function category()
    {
        return $this->category;
    }
}


