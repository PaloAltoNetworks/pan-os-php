<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018 Christophe Painchaud <shellescape _AT_ gmail.com>
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


class AppCustom extends App
{
    use XmlConvertible;

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getAppCustomStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function load_from_domxml( $appx )
    {

            //TODO: not implemented yet: <description>custom_app</description>

            $signaturecur = DH::findFirstElement('signature', $appx);
            if( $signaturecur !== FALSE )
            {
                $this->custom_signature = TRUE;
            }

            $parentappcur = DH::findFirstElement('parent-app', $appx);
            if( $parentappcur !== FALSE )
            {
                //TODO: implementation needed of $this->parent_app
                #$this->parent_app = $parentappcur->textContent;
            }

            $timeoutcur = DH::findFirstElement('timeout', $appx);
            if( $timeoutcur !== FALSE )
            {
                $this->timeout = $timeoutcur->textContent;
            }
            $tcptimeoutcur = DH::findFirstElement('tcp-timeout', $appx);
            if( $tcptimeoutcur !== FALSE )
            {
                $this->tcp_timeout = $tcptimeoutcur->textContent;
            }
            $udptimeoutcur = DH::findFirstElement('udp-timeout', $appx);
            if( $udptimeoutcur !== FALSE )
            {
                $this->udp_timeout = $udptimeoutcur->textContent;
            }
            $tcp_half_timeoutcur = DH::findFirstElement('tcp-half-closed-timeout', $appx);
            if( $tcp_half_timeoutcur !== FALSE )
            {
                $this->tcp_half_closed_timeout = $tcp_half_timeoutcur->textContent;
            }
            $tcp_wait_timeoutcur = DH::findFirstElement('tcp-time-wait-timeout', $appx);
            if( $tcp_wait_timeoutcur !== FALSE )
            {
                $this->tcp_time_wait_timeout = $tcp_wait_timeoutcur->textContent;
            }

            $cursor = DH::findFirstElement('default', $appx);
            if( $cursor !== FALSE )
            {
                $protocur = DH::findFirstElement('ident-by-ip-protocol', $cursor);
                if( $protocur !== FALSE )
                {
                    $this->proto = $protocur->textContent;
                }

                $icmpcur = DH::findFirstElement('ident-by-icmp-type', $cursor);
                if( $icmpcur !== FALSE )
                {
                    $icmptype = DH::findFirstElement('type', $icmpcur);
                    if( $icmptype !== FALSE )
                    {
                        $this->icmpsub = $icmptype->textContent;
                    }

                    $icmpcode = DH::findFirstElement('code', $icmpcur);
                    if( $icmpcode !== FALSE )
                    {
                        $this->icmpcode = $icmpcode->textContent;
                    }
                }

                $icmp6cur = DH::findFirstElement('ident-by-icmp6-type', $cursor);
                if( $icmp6cur !== FALSE )
                {
                    $icmp6type = DH::findFirstElement('type', $icmp6cur);
                    if( $icmp6type !== FALSE )
                    {
                        $this->icmp6sub = $icmp6type->textContent;
                    }

                    $icmp6code = DH::findFirstElement('code', $icmp6cur);
                    if( $icmp6code !== FALSE )
                    {
                        $this->icmp6code = $icmp6code->textContent;
                    }
                }

                $cursor = DH::findFirstElement('port', $cursor);
                if( $cursor !== FALSE )
                {
                    foreach( $cursor->childNodes as $portx )
                    {
                        if( $portx->nodeType != XML_ELEMENT_NODE )
                            continue;

                        /** @var  $portx DOMElement */

                        $ex = explode('/', $portx->textContent);

                        if( count($ex) != 2 )
                            derr('unsupported port description: ' . $portx->textContent);

                        if( $ex[0] == 'tcp' )
                        {
                            $exports = explode(',', $ex[1]);
                            $ports = array();

                            if( count($exports) < 1 )
                                derr('unsupported port description: ' . $portx->textContent);

                            foreach( $exports as &$sport )
                            {
                                if( $sport == 'dynamic' )
                                {
                                    $ports[] = array(0 => 'dynamic');
                                    continue;
                                }
                                $tmpex = explode('-', $sport);
                                if( count($tmpex) < 2 )
                                {
                                    $ports[] = array(0 => 'single', 1 => $sport);
                                    continue;
                                }

                                $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                            }
                            //print_r($ports);

                            if( $this->tcp === null )
                                $this->tcp = $ports;
                            else
                                $this->tcp = array_merge($this->tcp, $ports);
                        }
                        elseif( $ex[0] == 'udp' )
                        {
                            $exports = explode(',', $ex[1]);
                            $ports = array();

                            if( count($exports) < 1 )
                                derr('unsupported port description: ' . $portx->textContent);

                            foreach( $exports as &$sport )
                            {
                                if( $sport == 'dynamic' )
                                {
                                    $ports[] = array(0 => 'dynamic');
                                    continue;
                                }
                                $tmpex = explode('-', $sport);
                                if( count($tmpex) < 2 )
                                {
                                    $ports[] = array(0 => 'single', 1 => $sport);
                                    continue;
                                }

                                $ports[] = array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

                            }
                            //print_r($ports);

                            if( $this->udp === null )
                                $this->udp = $ports;
                            else
                                $this->udp = array_merge($this->udp, $ports);
                        }
                        elseif( $ex[0] == 'icmp' )
                        {
                            $this->icmp = $ex[1];
                        }
                        elseif( $ex[0] == 'icmp6' )
                        {
                            $this->icmp6 = $ex[1];
                        }
                        else
                            derr('unsupported port description: ' . $portx->textContent);
                    }
                }
            }


            $this->app_filter_details = array();

            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== FALSE )
            {
                $this->category = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== FALSE )
            {
                $this->subCategory = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== FALSE )
            {
                $this->technology = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== FALSE )
            {
                $this->risk = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('evasive-behavior', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['evasive'] = TRUE;
            }
            $tmp = DH::findFirstElement('consume-big-bandwidth', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['excessive-bandwidth'] = TRUE;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['used-by-malware'] = TRUE;
            }
            $tmp = DH::findFirstElement('able-to-transfer-files', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['transfers-files'] = TRUE;
            }
            $tmp = DH::findFirstElement('has-known-vulnerabilities', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['vulnerabilities'] = TRUE;
            }
            $tmp = DH::findFirstElement('tunnels-other-apps', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['tunnels-other-apps'] = TRUE;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['prone-to-misuse'] = TRUE;
            }

            $tmp = DH::findFirstElement('pervasive-use', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->_characteristics['widely-used'] = TRUE;
            }


            $tmp = DH::findFirstElement('virusident-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->virusident = TRUE;
            }
            $tmp = DH::findFirstElement('filetype-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->filetypeident = TRUE;
            }
            $tmp = DH::findFirstElement('data-ident', $appx);
            if( $tmp !== FALSE )
            {
                if( $tmp->textContent == 'yes' )
                    $this->fileforward = TRUE;
            }
    }

}