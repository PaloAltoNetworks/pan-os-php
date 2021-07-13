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
// - containercreate / devicecloudcreate
// - devicegroupsetparent
// - containersetparent / deviceloudsetparent
// - templatemovesharedtovsys
// - templatestackmovetofirsttemplate

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
                print $context->padding." - " . get_class($template) . " '{$template->name()}'  ";
                print "\n";
            }
            //Todo: print where this TemplateStack is used SERIAL
        }
        elseif( get_class($object) == "DeviceGroup" )
        {
            $parentDGS = $object->parentDeviceGroups();
            $parentDGS['shared'] = $object->owner;


            $tmp_padding = "";
            foreach( array_reverse( $parentDGS ) as $key => $DG)
            {
                print $context->padding.$tmp_padding."- ".$key."\n";
                $tmp_padding .= "  ";
            }
            //Todo: print complete DG Hierarchy
        }
        elseif( get_class($object) == "Template" )
        {
            //Todo: print where this template is used // full templateStack hierarchy
        }

        print "\n";
    },
);
DeviceCallContext::$supportedActions[] = array(
    'name' => 'displaymanageddevices',
    'MainFunction' => function (DeviceCallContext $context) {
        $managedDevice = $context->object;
        $device = $managedDevice->owner->owner;

        $padding = "       ";

        if( get_class( $managedDevice ) !== "ManagedDevice" )
            return false;

        /** @var ManagedDevice */

        if( $managedDevice->getDeviceGroup() != null )
            print $padding."DG: ".$managedDevice->getDeviceGroup()."\n";
        if( $managedDevice->getTemplate() != null )
            print $padding."Template: ".$managedDevice->getTemplate()."\n";
        if( $managedDevice->getTemplateStack() != null )
        {
            print $padding."TempalteStack: ".$managedDevice->getTemplateStack()."\n";
            $templatestack = $device->findTemplateStack( $managedDevice->getTemplateStack() );
            foreach( $templatestack->templates as $template )
            {
                $template_obj = $device->findTemplate( $template );
                if( $template_obj !== null )
                    print " - ".$template_obj->name()."\n";
            }
        }

        return true;

    },
);
DeviceCallContext::$supportedActions['DeviceGroupcreate'] = array(
    'name' => 'devicegroupcreate',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
    },
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $dgName = $context->arguments['name'];
        $parentDG = $context->arguments['parentdg'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( $parentDG != 'false' )
        {
            $tmp_parentdg = $pan->findDeviceGroup( $parentDG );
            if( $tmp_parentdg === null )
            {
                print "     - SKIP parentDG set with '".$parentDG."' but not found on this config\n";
                $parentDG = null;
            }
        }

        $tmp_dg = $pan->findDeviceGroup( $dgName );
        if( $tmp_dg === null )
        {
            print "     * create DeviceGroup: ".$dgName."\n";
            $pan->createDeviceGroup( $dgName, $parentDG );
        }
        else
            print "     * DeviceGroup with name: ".$dgName." already available!\n";
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'parentdg' => array('type' => 'string', 'default' => 'null'),
    ),
);
DeviceCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        $lines = '';
        $encloseFunction = function ($value, $nowrap = TRUE) {
            if( is_string($value) )
                $output = htmlspecialchars($value);
            elseif( is_array($value) )
            {
                $output = '';
                $first = TRUE;
                foreach( $value as $subValue )
                {
                    if( !$first )
                    {
                        $output .= '<br />';
                    }
                    else
                        $first = FALSE;

                    if( is_string($subValue) )
                        $output .= htmlspecialchars($subValue);
                    else
                        $output .= htmlspecialchars($subValue->name());
                }
            }
            else
                derr('unsupported');

            if( $nowrap )
                return '<td style="white-space: nowrap">' . $output . '</td>';

            return '<td>' . $output . '</td>';
        };


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        #$headers = '<th>location</th><th>name</th><th>template</th>';
        $headers = '<th>name</th><th>template</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var Tag $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                #$lines .= $encloseFunction(PH::getLocationString($object));

                $lines .= $encloseFunction($object->name());

                if( get_class($object) == "TemplateStack" )
                {
                    $lines .= $encloseFunction( array_reverse($object->templates) );
                }

                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $encloseFunction($refTextArray);
                }

                $lines .= "</tr>\n";
            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html-export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);
DeviceCallContext::$supportedActions['template-add'] = array(
    'name' => 'template-add',
    'MainFunction' => function (DeviceCallContext $context) {

        /** @var TemplateStack $object */
        $object = $context->object;

        if( get_class($object) == "TemplateStack" )
        {
            $templateName = $context->arguments['templateName'];
            $position = $context->arguments['position'];


            $template = $object->owner->findTemplate( $templateName );

            if( $template == null )
            {
                print "     - SKIP adding template '".$templateName."' because it is not found in this config\n";
                return null;
            }

            if( $context->isAPI )
                $object->API_addTemplate( $template, $position );
            else
                $object->addTemplate( $template, $position );
        }
        print "\n";
    },
    'args' => array(
        'templateName' => array('type' => 'string', 'default' => 'false'),
        'position' => array('type' => 'string', 'default' => 'bottom'),
    ),
);