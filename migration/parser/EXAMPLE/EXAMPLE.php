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
class EXAMPLE extends PARSER
{
    public function vendor_main()
    {

        //check if this can not be done better
        $this->getDeviceConfig( $this->sub, $this->template, $this->template_vsys);
        //#################################################################################
        //#################################################################################


        global $print;
        $print = TRUE;


        $this->clean_config();


        $this->import_config(); //This should update the $source
        CONVERTER::validate_interface_names($this->template);
        CONVERTER::cleanup_unused_predefined_services($this->sub, "default");

        CONVERTER::deleteDirectory( );
    }

    function clean_config()
    {
        $config_file = file($this->configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->data = array();
        foreach( $config_file as $line => $names_line )
        {
            $this->data[] = $names_line;
        }
        #file_put_contents("test_output.txt", $this->data);
        #file_put_contents('test_output.txt', print_r($this->data, true));
    }

    /**
     * @param PANConf $pan
     */
    function import_config()
    {
        // We create/import a base-config first.
        // Use this vsys in the base config that was imported:
        $vsysName = "Example";
        $vsysID = 1;
        $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);
        if( $this->template_vsys === null )
        {
            $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            $this->template_vsys->setAlternativeName($vsysName);
        }
        else
        {
            //create new vsys, search for latest ID
            do
            {
                $vsysID++;
                $this->template_vsys = $this->template->findVirtualSystem('vsys' . $vsysID);
            } while( $this->template_vsys !== null );
            if( $this->template_vsys === null )
            {
                $this->template_vsys = $this->template->createVirtualSystem(intval($vsysID), $vsysName . $vsysID);
                if( $this->template_vsys === null )
                {
                    derr("vsys" . $vsysID . " could not be created ? Exit\n");
                }
            }
        }
        echo PH::boldText("\nObject_network loaded\n");
        #get_object_network($this->data, $v);
        echo PH::boldText("\nsave_names:\n");
        echo PH::boldText("\nload custome application:\n");
        #load_customer_application($v);
        #get_interfaces($cisco_config_file, $source, $vsys, $template);
        echo PH::boldText("\nget interfaces:\n");
        #get_interfaces($this->data, $v);
        #get_static_routes($cisco_config_file, $source, $vsys, $template);
        echo PH::boldText("\nget static routes\n");
        #get_static_routes($this->data, $v);
        echo PH::boldText("\nObjectGroup_network loaded\n");
        #get_objectgroup_network2($this->data, $v);
        echo PH::boldText("\n SERVICES \n");

        echo PH::boldText("\nServices loaded\n");
        #get_object_service($this->data, $v);
        echo PH::boldText("\nObject_services loaded\n");
        #get_objectgroup_service($this->data, $v);
        echo PH::boldText("\nProtocol groups loaded\n");
        #get_protocol_groups($this->data, $v);
        echo PH::boldText("\nICMPGroups loaded\n");
        #get_icmp_groups($this->data, $v);
        echo PH::boldText("\nNAT twice 'before':\n");
        #get_twice_nats($this->data, $v, "before");
        echo PH::boldText("\nNAT objects:'\n");
        #get_objects_nat($this->data, $v);
        echo PH::boldText("\nNAT twice 'after':\n");
        #get_twice_nats($this->data, $v, "after");
        print "NAT counter: " . $this->sub->natRules->count() . "\n";
        $userObj = array();
        echo PH::boldText("\nget objectgroup user\n");
        echo PH::boldText("\nget security Policy\n");
        #get_security_policies2($this->data, $v);
        return $v;
        clean_zone_any($source, $vsys);
    }
}
