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

//Todo:
// - create template-stack ( add to FW device (serial#))
// - create template (incl adding to template-stack)
// - add devicegroup to FW device serial#
// - create devicegroup with extension to  DG parent
// - filter for template-stack has template

DeviceCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        print "     * " . get_class($object) . " '{$object->name()}'  ";
        print "\n";


        if( get_class($object) == "TemplateStack" )
        {
            $used_templates = $object->templates;
            foreach( $used_templates as $template )
            {
                print "        - " . get_class($template) . " '{$template->name()}'  ";
                print "\n";
            }
            //Todo: print where this TemplateStack is used SERIAL
        }
        elseif( get_class($object) == "DeviceGroup" )
        {
            //Todo: print complete DG Hierarchy
        }
        elseif( get_class($object) == "Template" )
        {
            //Todo: print where this template is used // full templateStack hierarchy
        }

        print "\n";
    },
);
DeviceCallContext::$supportedActions['createDeviceGroup'] = array(
    'name' => 'createdevicegroup',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
    },
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $dgName = $context->arguments['name'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        $tmp_dg = $pan->findDeviceGroup( $dgName );
        if( $tmp_dg === null )
        {
            print " * create DeviceGroup: ".$dgName."\n";
            $pan->createDeviceGroup( $dgName );
        }
        else
            print " * DeviceGroup with name: ".$dgName." already available!\n";
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
    ),
);