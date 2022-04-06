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
        PH::print_stdout( "     * " . get_class($object) . " '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();
        PH::$JSON_TMP['sub']['object'][$object->name()]['type'] = get_class($object);

        if( get_class($object) == "TemplateStack" )
        {
            $used_templates = $object->templates;
            foreach( $used_templates as $template )
            {
                PH::print_stdout( $context->padding." - " . get_class($template) . " '{$template->name()}'" );
                PH::$JSON_TMP['sub']['object'][$object->name()]['template'][] = $template->name();
            }
            //Todo: PH::print_stdout( where this TemplateStack is used SERIAL
        }
        elseif( get_class($object) == "VirtualSystem" )
        {
            /** @var VirtualSystem $object */
            PH::print_stdout( $context->padding." - Name: '{$object->alternativeName()}'" );
            PH::$JSON_TMP['sub']['object'][$object->name()]['alternativename'] = $object->alternativeName();
        }
        elseif( get_class($object) == "DeviceGroup" )
        {
            $parentDGS = $object->parentDeviceGroups();
            $parentDGS['shared'] = $object->owner;


            $tmp_padding = "";
            foreach( array_reverse( $parentDGS ) as $key => $DG)
            {
                PH::print_stdout( $context->padding.$tmp_padding."- ".$key );
                $tmp_padding .= "  ";
                PH::$JSON_TMP['sub']['object'][$object->name()]['hierarchy'][] = $key;
            }
            foreach( $object->getDevicesInGroup() as $key => $device )
            {
                PH::print_stdout( $context->padding."- ".$key );
                PH::$JSON_TMP['sub']['object'][$object->name()]['devices'][] = $key;
            }


        }
        elseif( get_class($object) == "ManagedDevice" )
        {
            $managedDevice = $context->object;
            $device = $managedDevice->owner->owner;

            $padding = "       ";
            /** @var ManagedDevice $managedDevice */

            if( $managedDevice->getDeviceGroup() != null )
            {
                PH::print_stdout( $padding."DG: ".$managedDevice->getDeviceGroup() );
                PH::$JSON_TMP['sub']['object'][$object->name()]['dg'] = $managedDevice->getDeviceGroup();
            }


            if( $managedDevice->getTemplate() != null )
            {
                PH::print_stdout( $padding."Template: ".$managedDevice->getTemplate() );
                PH::$JSON_TMP['sub']['object'][$object->name()]['template'] = $managedDevice->getTemplate();
            }


            if( $managedDevice->getTemplateStack() != null )
            {
                PH::print_stdout( $padding."TempalteStack: ".$managedDevice->getTemplateStack() );
                PH::$JSON_TMP['sub']['object'][$object->name()]['templatestack'][$managedDevice->getTemplateStack()]['name'] = $managedDevice->getTemplateStack();

                $templatestack = $device->findTemplateStack( $managedDevice->getTemplateStack() );
                foreach( $templatestack->templates as $template )
                {
                    $template_obj = $device->findTemplate( $template );
                    if( $template_obj !== null )
                    {
                        PH::print_stdout( " - ".$template_obj->name() );
                        PH::$JSON_TMP['sub']['object'][$object->name()]['templatestack'][$managedDevice->getTemplateStack()]['templates'][] = $template_obj->name();
                    }

                }
            }

            if( $managedDevice->isConnected )
            {
                PH::print_stdout( $padding."connected" );
                PH::print_stdout( $padding."IP-Address: ".$managedDevice->mgmtIP );
                PH::print_stdout( $padding."Hostname: ".$managedDevice->hostname );
                PH::print_stdout( $padding."PAN-OS: ".$managedDevice->version );
                PH::print_stdout( $padding."Model: ".$managedDevice->model );
                PH::$JSON_TMP['sub']['object'][$object->name()]['connected'] = "true";
                PH::$JSON_TMP['sub']['object'][$object->name()]['hostname'] = $managedDevice->hostname;
                PH::$JSON_TMP['sub']['object'][$object->name()]['ip-address'] = $managedDevice->mgmtIP;
                PH::$JSON_TMP['sub']['object'][$object->name()]['sw-version'] = $managedDevice->version;
                PH::$JSON_TMP['sub']['object'][$object->name()]['model'] = $managedDevice->model;
            }

        }
        elseif( get_class($object) == "Template" )
        {
            //Todo: PH::print_stdout( where this template is used // full templateStack hierarchy
        }

        PH::print_stdout( "" );
    },
);
DeviceCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;

        if( get_class($object) == "TemplateStack" )
        {

        }
        elseif( get_class($object) == "Template" )
        {
            //Todo: Templates are not displaying templatestack until now
            $object->display_references(7);
        }
        elseif( get_class($object) == "VirtualSystem" )
        {
            /** @var VirtualSystem $object */
        }
        elseif( get_class($object) == "DeviceGroup" )
        {

        }
        elseif( get_class($object) == "ManagedDevice" )
        {
            //serial is references in DG / template-stack, but also in Securityrules as target
            //Todo: secrule target is missing until now
            $object->display_references(7);
        }

        return null;

    },
);
DeviceCallContext::$supportedActions['DeviceGroup-create'] = array(
    'name' => 'devicegroup-create',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $dgName = $context->arguments['name'];
        $parentDG = $context->arguments['parentdg'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");

        if( $parentDG != 'null' )
        {
            $tmp_parentdg = $pan->findDeviceGroup($parentDG);
            if( $tmp_parentdg === null )
            {
                $string = "parentDG set with '" . $parentDG . "' but not found on this config";
                PH::ACTIONstatus($context, "SKIPPED", $string);
                $parentDG = null;
            }
        }

        $tmp_dg = $pan->findDeviceGroup($dgName);
        if( $tmp_dg === null )
        {
            $string = "create DeviceGroup: " . $dgName;
            #PH::ACTIONlog($context, $string);
            if( $parentDG === 'null' )
                $parentDG = null;

            $dg = $pan->createDeviceGroup($dgName, $parentDG);

            if( $context->isAPI )
                $dg->API_sync();
        }
        else
        {
            $string = "DeviceGroup with name: " . $dgName . " already available!";
            PH::ACTIONlog( $context, $string );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
        'parentdg' => array('type' => 'string', 'default' => 'null'),
    ),
);
DeviceCallContext::$supportedActions['DeviceGroup-delete'] = array(
    'name' => 'devicegroup-delete',
    'MainFunction' => function (DeviceCallContext $context) {

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "DeviceGroup" )
        {
            $childDG = $object->_childDeviceGroups;
            if( count($childDG) != 0 )
            {
                $string = "DG with name: '" . $name . "' has ChildDGs. DG can not removed";
                PH::ACTIONstatus($context, "SKIPPED", $string);
            }
            else
            {
                $string ="     * delete DeviceGroup: " . $name;
                PH::ACTIONlog( $context, $string );


                if( $context->isAPI )
                {
                    $con = findConnectorOrDie($object);
                    $xpath = DH::elementToPanXPath($object->xmlroot);

                    $pan->removeDeviceGroup($object);
                    $con->sendDeleteRequest($xpath);
                }
                else
                    $pan->removeDeviceGroup($object);

            }
        }
    }
);
DeviceCallContext::$supportedActions['Template-create'] = array(
    'name' => 'template-create',
    'MainFunction' => function (DeviceCallContext $context) {
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context) {
        $templateName = $context->arguments['name'];

        $pan = $context->subSystem;

        if( !$pan->isPanorama() )
            derr("only supported on Panorama config");


        $tmp_template = $pan->findTemplate($templateName);
        if( $tmp_template === null )
        {
            $string = "create Template: " . $templateName;
            #PH::ACTIONlog($context, $string);

            $dg = $pan->createTemplate($templateName);

            if( $context->isAPI )
                $dg->API_sync();
        }
        else
        {
            $string = "Template with name: " . $templateName . " already available!";
            PH::ACTIONlog( $context, $string );
        }
    },
    'args' => array(
        'name' => array('type' => 'string', 'default' => 'false'),
    ),
);
DeviceCallContext::$supportedActions['Template-delete'] = array(
    'name' => 'template-delete',
    'MainFunction' => function (DeviceCallContext $context) {

        $object = $context->object;
        $name = $object->name();

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "Template" )
        {
            /** @var Template $object */
            //if template is used in Template-Stack -> skip
            /*
            $childDG = $object->_childDeviceGroups;
            if( count($childDG) != 0 )
            {
                $string = "Template with name: '" . $name . "' is used in TemplateStack. Template can not removed";
                PH::ACTIONstatus($context, "SKIPPED", $string);
            }
            else
            {
            */
                $string ="     * delete Template: " . $name;
                PH::ACTIONlog( $context, $string );


                if( $context->isAPI )
                {
                    $con = findConnectorOrDie($object);
                    $xpath = DH::elementToPanXPath($object->xmlroot);

                    $pan->removeTemplate($object);
                    $con->sendDeleteRequest($xpath);
                }
                else
                    $pan->removeTemplate($object);

            //}
        }
    }
);

DeviceCallContext::$supportedActions['exportToExcel'] = array(
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

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

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

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
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

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "TemplateStack" )
        {
            $templateName = $context->arguments['templateName'];
            $position = $context->arguments['position'];


            $template = $object->owner->findTemplate( $templateName );

            if( $template == null )
            {
                $string = "adding template '".$templateName."' because it is not found in this config";
                PH::ACTIONstatus( $context, "SKIPPED", $string );

                return null;
            }

            if( $context->isAPI )
                $object->API_addTemplate( $template, $position );
            else
                $object->addTemplate( $template, $position );
        }
        PH::print_stdout( "" );
    },
    'args' => array(
        'templateName' => array('type' => 'string', 'default' => 'false'),
        'position' => array('type' => 'string', 'default' => 'bottom'),
    ),
);
DeviceCallContext::$supportedActions['AddressStore-rewrite'] = array(
    'name' => 'addressstore-rewrite',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {

        /** @var DeviceGroup $object */
        $object = $context->object;

        $pan = $context->subSystem;
        if( !$pan->isPanorama() )
            derr( "only supported on Panorama config" );

        if( get_class($object) == "DeviceGroup" )
        {
            if( $context->first )
            {
                $object->owner->addressStore->rewriteAddressStoreXML();
                $object->owner->addressStore->rewriteAddressGroupStoreXML();
                $context->first = false;
            }

            $object->addressStore->rewriteAddressStoreXML();
            $object->addressStore->rewriteAddressGroupStoreXML();
        }

    }
  //rewriteAddressStoreXML()
);
DeviceCallContext::$supportedActions['exportInventoryToExcel'] = array(
    'name' => 'exportInventoryToExcel',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
        $context->fields = array();
        $context->device_array = array();
    },
    'MainFunction' => function (DeviceCallContext $context)
    {

        if( $context->first && get_class($context->object) == "ManagedDevice" )
        {
            $connector = findConnectorOrDie($context->object);
            $context->device_array = $connector->panorama_getAllFirewallsSerials();


            foreach( $context->device_array as $index => &$array )
            {
                foreach( $array as $key => $value )
                    $context->fields[$key] = $key;
            }


            foreach( $context->device_array as $index => &$array )
            {
                foreach( $context->fields as $key => $value )
                {
                    if( !isset( $array[$key] ) )
                        $array[$key] = "not set";
                }
            }
        }

    },
    'GlobalFinishFunction' => function (DeviceCallContext $context)
    {
        $content = "";
        if( get_class($context->object) == "ManagedDevice" )
        {
            $lines = '';

            $count = 0;
            if( !empty($context->device_array) )
            {
                foreach ($context->device_array as $device)
                {
                    $count++;

                    /** @var SecurityRule|NatRule $rule */
                    if ($count % 2 == 1)
                        $lines .= "<tr>\n";
                    else
                        $lines .= "<tr bgcolor=\"#DDDDDD\">";

                    foreach($context->fields as $fieldName => $fieldID )
                    {
                        $lines .= "<td>".$device[$fieldID]."</td>";
                    }
                    $lines .= "</tr>\n";
                }
            }

            $tableHeaders = '';
            foreach($context->fields as $fName => $value )
                $tableHeaders .= "<th>{$fName}</th>\n";

            $content = file_get_contents(dirname(__FILE__).'/html/export-template.html');


            $content = str_replace('%TableHeaders%', $tableHeaders, $content);

            $content = str_replace('%lines%', $lines, $content);

            $jscontent =  file_get_contents(dirname(__FILE__).'/html/jquery.min.js');
            $jscontent .= "\n";
            $jscontent .= file_get_contents(dirname(__FILE__).'/html/jquery.stickytableheaders.min.js');
            $jscontent .= "\n\$('table').stickyTableHeaders();\n";

            $content = str_replace('%JSCONTENT%', $jscontent, $content);
        }
        file_put_contents($context->arguments['filename'], $content);
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "only usable with 'devicetype=manageddevice'"
        )
    )
);
DeviceCallContext::$supportedActions['exportLicenseToExcel'] = array(
    'name' => 'exportLicenseToExcel',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
        $context->fields = array();
        $context->device_array = array();
    },
    'MainFunction' => function (DeviceCallContext $context)
    {

        if( $context->first && get_class($context->object) == "ManagedDevice" )
        {
            $connector = findConnectorOrDie($context->object);
            $configRoot = $connector->sendOpRequest( '<request><batch><license><info></info></license></batch></request>' );



            $configRoot = DH::findFirstElement('result', $configRoot);
            if( $configRoot === FALSE )
                derr("<result> was not found", $configRoot);

            $configRoot = DH::findFirstElement('devices', $configRoot);
            if( $configRoot === FALSE )
                derr("<config> was not found", $configRoot);


#var_dump( $configRoot );

            foreach( $configRoot->childNodes as $entry )
            {
                if( $entry->nodeType != XML_ELEMENT_NODE )
                    continue;

                foreach( $entry->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;


                    if( $node->nodeName == "serial" ||  $node->nodeName == "serial-no" )
                    {
                        #print $node->nodeName." : ".$node->textContent."\n";
                        $serial_no = $node->textContent;
                        $context->device_array[ $serial_no ][ $node->nodeName ] = $serial_no;
                    }
                    else
                    {
                        #print $node->nodeName." : ".$node->textContent."\n";
                        $tmp_node = $node->textContent;
                        $context->device_array[ $tmp_node ][ $node->nodeName ] = $tmp_node;

                        if( $node->childNodes->length > 1 )
                        {
                            foreach( $node->childNodes as $child )
                            {
                                if( $node->nodeType != XML_ELEMENT_NODE )
                                    continue;


                                if( $child->nodeName == "entry" )
                                {
                                    $tmp_node = $child->textContent;
                                    $context->device_array[ $tmp_node ][ $child->getAttribute('name') ] = $tmp_node;
                                }
                            }
                        }
                    }
                }
            }

            foreach( $context->device_array as $index => &$array )
            {
                foreach( $array as $key => $value )
                    $context->fields[$key] = $key;
            }


            foreach( $context->device_array as $index => &$array )
            {
                foreach( $context->fields as $key => $value )
                {
                    if( !isset( $array[$key] ) )
                        $array[$key] = "- - - - -";
                }
            }
        }
    },
    'GlobalFinishFunction' => function (DeviceCallContext $context)
    {
        $content = "";
        if( get_class($context->object) == "ManagedDevice" )
        {
            $lines = '';

            $count = 0;
            if( !empty($context->device_array) )
            {
                foreach ($context->device_array as $device)
                {
                    $count++;

                    /** @var SecurityRule|NatRule $rule */
                    if ($count % 2 == 1)
                        $lines .= "<tr>\n";
                    else
                        $lines .= "<tr bgcolor=\"#DDDDDD\">";

                    foreach($context->fields as $fieldName => $fieldID )
                    {
                        $lines .= "<td>".$device[$fieldID]."</td>";
                    }

                    $lines .= "</tr>\n";
                }
            }


            $tableHeaders = '';
            foreach($context->fields as $fName => $value )
                $tableHeaders .= "<th>{$fName}</th>\n";

            $content = file_get_contents(dirname(__FILE__).'/html/export-template.html');


            $content = str_replace('%TableHeaders%', $tableHeaders, $content);

            $content = str_replace('%lines%', $lines, $content);

            $jscontent =  file_get_contents(dirname(__FILE__).'/html/jquery.min.js');
            $jscontent .= "\n";
            $jscontent .= file_get_contents(dirname(__FILE__).'/html/jquery.stickytableheaders.min.js');
            $jscontent .= "\n\$('table').stickyTableHeaders();\n";

            $content = str_replace('%JSCONTENT%', $jscontent, $content);


        }

        file_put_contents($context->arguments['filename'], $content);
    },
    'args' => array(
        'filename' => array('type' => 'string', 'default' => '*nodefault*',
        'help' => "only usable with 'devicetype=manageddevice'"
        )
    )
);

DeviceCallContext::$supportedActions['display-shadowrule'] = array(
    'name' => 'display-shadowrule',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        if( !$context->isAPI )
            derr( "API mode needed for actions=display-shadowrule" );
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->object->version < 91 )
            derr( "PAN-OS >= 9.1 is needed for display-shadowrule", null, false );

        $shadowArray = array();
        if( $classtype == "VirtualSystem" )
        {
            $type = "vsys";
            $type_name = $object->name();
            $countInfo = "<" . $type . ">" . $type_name . "</" . $type . ">";

            $shadowArray = $context->connector->getShadowInfo($countInfo, false);
        }
        elseif( $classtype == "ManagedDevice" )
        {
            if( $object->isConnected )
            {
                $type = "device-serial";
                $type_name = $object->name();
                $countInfo = "<" . $type . ">" . $type_name . "</" . $type . ">";

                $shadowArray = $context->connector->getShadowInfo($countInfo, true);
            }
        }
        elseif( $classtype == "DeviceGroup" )
        {
            /** @var DeviceGroup $object */
            $devices = $object->getDevicesInGroup();

            $shadowArray = array();
            foreach( $devices as $serial => $device )
            {
                $managedDevice = $object->owner->managedFirewallsStore->find( $serial );
                if( $managedDevice->isConnected )
                {
                    $type = "device-serial";
                    $type_name = $managedDevice->name();
                    $countInfo = "<" . $type . ">" . $type_name . "</" . $type . ">";

                    $shadowArray2 = $context->connector->getShadowInfo($countInfo, true);
                    $shadowArray = array_merge( $shadowArray, $shadowArray2 );
                }
            }
            //try to only use active device / skip passive FW
        }


        $jsonArray = array();
        foreach( $shadowArray as $name => $array )
        {
            foreach( $array as $ruletype => $entries )
            {
                if( $ruletype == 'security'  || $ruletype == "security-rule" )
                    $ruletype = "securityRules";
                elseif( $ruletype == 'nat'  || $ruletype == "nat-rule" )
                    $ruletype = "natRules";
                elseif( $ruletype == 'decryption' || $ruletype == "ssl-rule" )
                    $ruletype = "decryptionRules";
                else
                {
                    mwarning( "bugfix needed for type: ".$ruletype, null, false );
                    $ruletype = "securityRules";
                }


                if( $classtype == "ManagedDevice" )
                {
                    $subName = "DG";
                    PH::print_stdout( "     ** ".$subName.": " . $name );
                }

                foreach( $entries as $key => $item  )
                {
                    $rule = null;
                    $replace =  null;

                    //uid: $key -> search rule name for uid
                    if( $classtype == "ManagedDevice" )
                    {
                        /** @var PanoramaConf $pan */
                        $pan = $object->owner->owner;

                        /** @var DeviceGroup $sub */
                        $sub = $pan->findDeviceGroup($name);

                        $rule = $sub->$ruletype->findByUUID( $key );
                        while( $rule === null )
                        {
                            $sub = $sub->parentDeviceGroup;
                            if( $sub !== null )
                            {
                                $rule = $sub->$ruletype->findByUUID( $key );
                                $ownerDG = $sub->name();
                            }
                            else
                            {
                                $rule = $pan->$ruletype->findByUUID( $key );
                                $ownerDG = "shared";
                                if( $rule === null )
                                    break;
                            }
                        }
                    }
                    elseif( $classtype == "VirtualSystem" )
                    {
                        /** @var PANConf $pan */
                        $pan = $object->owner;

                        /** @var VirtualSystem $sub */
                        $sub = $pan->findVirtualSystem( $name );
                        $rule = $sub->$ruletype->findByUUID( $key );
                        $ownerDG = $name;

                        if( $rule === null )
                        {
                            $ruleArray = $sub->$ruletype->resultingRuleSet();
                            foreach( $ruleArray as $ruleSingle )
                            {
                                /** @var SecurityRule $ruleSingle */
                                if( $ruleSingle->uuid() === $key )
                                {
                                    $rule = $ruleSingle;
                                    $ownerDG = "panoramaPushedConfig";
                                }
                            }
                        }

                        if( $rule !== null )
                            $replace = "Rule '".$rule->name()."'";
                    }
                    elseif( $classtype == "DeviceGroup" )
                    {
                        /** @var PanoramaConf $pan */
                        $pan = $object->owner;

                        $rule = $object->$ruletype->findByUUID( $key );
                        $sub = $object;

                        while( $rule === null )
                        {
                            $sub = $sub->parentDeviceGroup;
                            if( $sub !== null )
                            {
                                $rule = $sub->$ruletype->findByUUID( $key );
                                $ownerDG = $sub->name();
                            }
                            else
                            {
                                $rule = $pan->$ruletype->findByUUID( $key );
                                $ownerDG = "shared";
                                if( $rule === null )
                                    break;
                            }
                        }
                    }

                    PH::print_stdout("");
                    if( $rule !== null )
                    {
                        PH::print_stdout( "        * RULE of type ".$ruletype.": '" . $rule->name(). "' owner: '".$ownerDG."' shadows rule: " );
                        $tmpName = $rule->name();
                    }

                    else
                    {
                        PH::print_stdout( "        * RULE of type ".$ruletype.": '" . $key."'" );
                        $tmpName = $key;
                    }


                    foreach( $item as $shadow )
                    {
                        if( $replace !== null )
                            $shadow = str_replace( $replace, "", $shadow );

                        $shadow = str_replace( " shadows rule ", "", $shadow );
                        $shadow = str_replace( "shadows ", "", $shadow );
                        $shadow = str_replace( ".", "", $shadow );
                        $shadow = str_replace( "'", "", $shadow );
                        PH::print_stdout( "          - '" . $shadow."'" );
                        $jsonArray[$ruletype][$tmpName][] = $shadow;
                    }
                }
            }
        }

        PH::$JSON_TMP['sub'] = $jsonArray;
    }
);

DeviceCallContext::$supportedActions['geoIP-check'] = array(
    'name' => 'geoIP-check',
    'GlobalInitFunction' => function (DeviceCallContext $context) {


        if( $context->subSystem->isPanorama() )
        {
            derr( "this action can be only run against PAN-OS FW", null, false );
        }

        $geoip = str_pad("geoIP JSON: ", 15) ."----------";
        $panos_geoip = str_pad("PAN-OS: ", 15) ."----------";

        $prefix = $context->arguments['checkIP'];

        if( filter_var($prefix, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
        {
            $filename = "ipv6";
            $prefixArray = explode(':', $prefix);
            $pattern = '/^' . $prefixArray[0] . ':' . $prefixArray[1] . ':/';
        }
        elseif( filter_var($prefix, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) )
        {
            $filename = "ipv4";
            $prefixArray = explode('.', $prefix);
            $pattern = '/^' . $prefixArray[0] . './';
        }
        else
            derr("not a valid IP: " . $prefix);


        $filepath = dirname(__FILE__)."/../../lib/resources/geoip/data/";
        $file = $filepath."RegionCC" . $filename . ".json";
        if ( !file_exists($file) )
        {
            derr( "Maxmind geo2ip lite database not downloaded correctly for PAN-OS-PHP", null, false );
        }
        $fileLine = file_get_contents( $file );
        $array = json_decode($fileLine, TRUE);
        unset( $fileLine);

        foreach( $array as $countryKey => $country )
        {
            foreach( $country as $value )
            {
                if( preg_match($pattern, $value) )
                    $responseArray[$value] = $countryKey;
            }
        }
        unset( $array );


        foreach( $responseArray as $ipKey => $countryKey )
        {
            if( cidr::netMatch($ipKey, $prefix) > 0 )
                $geoip = str_pad("geoIP JSON: ", 15) . $countryKey . " - " . $ipKey;
        }


        //###################################################

        if( $context->isAPI && $filename !== "ipv6" )
        {
            $request = "<show><location><ip>" . $prefix . "</ip></location></show>";

            try
            {
                $candidateDoc = $context->connector->sendOpRequest($request);
            }
            catch(Exception $e)
            {
                PH::disableExceptionSupport();
                print " ***** an error occured : " . $e->getMessage() . "\n\n";
            }


            #print $geoip . "\n";
            #$candidateDoc->preserveWhiteSpace = FALSE;
            #$candidateDoc->formatOutput = TRUE;
            #print $candidateDoc->saveXML();


            $result = DH::findFirstElement('result', $candidateDoc);
            $entry = DH::findFirstElement('entry', $result);

            $country = $entry->getAttribute("cc");
            $ip = DH::findFirstElement('ip', $entry)->textContent;
            $countryName = DH::findFirstElement('country', $entry)->textContent;

            $panos_geoip = str_pad("PAN-OS: ", 15) . $country . " - " . $ip . " - " . $countryName;
        }
        elseif($filename === "ipv6")
        {
            PH::print_stdout("not working for PAN-OS - ipv6 syntax for 'show location ip' not yet clear");
        }

        PH::print_stdout("");
        PH::print_stdout("");
        PH::print_stdout($geoip);
        PH::print_stdout($panos_geoip);
        PH::print_stdout("");

    },
    'MainFunction' => function (DeviceCallContext $context)
    {
    },
    'args' => array(
        'checkIP' => array('type' => 'string', 'default' => '8.8.8.8',
            'help' => "checkIP is IPv4 or IPv6 host address",
        )
    )
);

DeviceCallContext::$supportedActions['sp_spg-create-alert-only-BP'] = array(
    'name' => 'sp_spg-create-alert-only-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        if( $context->subSystem->isPanorama() )
        {
            $countDG = count( $context->subSystem->getDeviceGroups() );
            if( $countDG == 0  )
            {
                #$dg = $context->subSystem->createDeviceGroup( "alert-only" );
                derr( "NO DG available; please run 'pa_device-edit in=InputConfig.xml out=OutputConfig.xml actions=devicegroup-create:DG-NAME' first", null, false );
            }
        }
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $pathString = dirname(__FILE__)."/../../iron-skillet";
            $av_xmlString_v8 = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_virus.xml");
            $av_xmlString_v9 = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_virus.xml");
            $av_xmlString_v10 = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_virus.xml");

            $as_xmlString_v8 = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_spyware.xml");
            $as_xmlString_v9 = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_spyware.xml");
            $as_xmlString_v10 = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_spyware.xml");

            $vp_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml");

            $url_xmlString_v8 = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_url_filtering.xml");
            $url_xmlString_v9 = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml");
            $url_xmlString_v10 = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml");

            $fb_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml");

            $wf_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml");

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $context->arguments['shared'] && !$context->subSystem->isFirewall() )
                    $sharedStore = $sub->owner;
                else
                    $sharedStore = $sub;

                $name = "Alert-Only";
                $ownerDocument = $sub->xmlroot->ownerDocument;

                if( $context->object->owner->version < 90 )
                    $customURLarray = array( "Black-List", "White-List", "Custom-No-Decrypt" );
                else
                    $customURLarray = array( "Block", "Allow", "Custom-No-Decrypt" );
                foreach( $customURLarray as $entry )
                {
                    $block = $sharedStore->customURLProfileStore->find($entry);
                    if( $block === null )
                    {
                        $block = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL($entry);
                        if( $context->isAPI )
                            $block->API_sync();
                    }
                }
                /*
                $block = $sharedStore->customURLProfileStore->find("Block");
                if( $block === null )
                {
                    $block = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL("Block");
                    if( $context->isAPI )
                        $block->API_sync();
                }
                $allow = $sharedStore->customURLProfileStore->find("Allow");
                if( $allow === null )
                {
                    $allow = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL("Allow");
                    if( $context->isAPI )
                        $allow->API_sync();
                }
                $nodecrypt = $sharedStore->customURLProfileStore->find("Custom-No-Decrypt");
                if( $nodecrypt === null )
                {
                    $nodecrypt = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL("Custom-No-Decrypt");
                    if( $context->isAPI )
                        $nodecrypt->API_sync();
                }*/


                $av = $sharedStore->AntiVirusProfileStore->find($name . "-AV");
                if( $av === null )
                {
                    $store = $sharedStore->AntiVirusProfileStore;
                    $av = new AntiVirusProfile($name . "-AV", $store);
                    $newdoc = new DOMDocument;
                    if( $context->object->owner->version < 90 )
                        $newdoc->loadXML($av_xmlString_v8);
                    elseif( $context->object->owner->version < 100 )
                        $newdoc->loadXML($av_xmlString_v9);
                    else
                        $newdoc->loadXML($av_xmlString_v10);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $name . "-AV", $node);
                    $node = $ownerDocument->importNode($node, TRUE);
                    $av->load_from_domxml($node);
                    $av->owner = null;
                    $store->addSecurityProfile($av);

                    if( $context->isAPI )
                        $av->API_sync();
                }

                $as = $sharedStore->AntiSpywareProfileStore->find($name . "-AS");
                if( $as === null )
                {
                    $store = $sharedStore->AntiSpywareProfileStore;
                    $as = new AntiSpywareProfile($name . "-AS", $store);
                    $newdoc = new DOMDocument;
                    if( $context->object->owner->version < 90 )
                        $newdoc->loadXML($as_xmlString_v8);
                    elseif( $context->object->owner->version < 100 )
                        $newdoc->loadXML($as_xmlString_v9);
                    else
                        $newdoc->loadXML($as_xmlString_v10);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $name . "-AS", $node);
                    $node = $newdoc->importNode($node, TRUE);
                    $node = $ownerDocument->importNode($node, TRUE);
                    $as->load_from_domxml($node);
                    $as->owner = null;
                    $store->addSecurityProfile($as);

                    if( $context->isAPI )
                        $as->API_sync();
                }

                $vp = $sharedStore->VulnerabilityProfileStore->find($name . "-VP");
                if( $vp === null )
                {
                    $store = $sharedStore->VulnerabilityProfileStore;
                    $vp = new VulnerabilityProfile($name . "-VP", $store);
                    $newdoc = new DOMDocument;
                    $newdoc->loadXML($vp_xmlString);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $name . "-VP", $node);
                    $node = $newdoc->importNode($node, TRUE);
                    $node = $ownerDocument->importNode($node, TRUE);
                    $vp->load_from_domxml($node);
                    $vp->owner = null;
                    $store->addSecurityProfile($vp);

                    if( $context->isAPI )
                        $vp->API_sync();
                }

                $url = $sharedStore->URLProfileStore->find($name . "-URL");
                if( $url === null )
                {
                    $store = $sharedStore->URLProfileStore;
                    $url = new URLProfile($name . "-URL", $store);
                    $newdoc = new DOMDocument;
                    if( $context->object->owner->version < 90 )
                        $newdoc->loadXML($url_xmlString_v8);
                    elseif( $context->object->owner->version < 100 )
                        $newdoc->loadXML($url_xmlString_v9);
                    else
                        $newdoc->loadXML($url_xmlString_v10);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $name . "-URL", $node);
                    $node = $newdoc->importNode($node, TRUE);
                    $node = $ownerDocument->importNode($node, TRUE);
                    $url->load_from_domxml($node);
                    $url->owner = null;
                    $store->addSecurityProfile($url);

                    if( $context->isAPI )
                        $url->API_sync();
                }

                $fb = $sharedStore->FileBlockingProfileStore->find($name . "-FB");
                if( $fb === null )
                {
                    $store = $sharedStore->FileBlockingProfileStore;
                    $fb = new FileBlockingProfile($name . "-FB", $store);
                    $newdoc = new DOMDocument;
                    $newdoc->loadXML($fb_xmlString);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $name . "-FB", $node);
                    $node = $newdoc->importNode($node, TRUE);
                    $node = $ownerDocument->importNode($node, TRUE);
                    $fb->load_from_domxml($node);
                    $fb->owner = null;
                    $store->addSecurityProfile($fb);

                    if( $context->isAPI )
                        $fb->API_sync();
                }

                $wf = $sharedStore->WildfireProfileStore->find($name . "-WF");
                if( $wf === null )
                {
                    $store = $sharedStore->WildfireProfileStore;
                    $wf = new WildfireProfile($name . "-WF", $store);
                    $newdoc = new DOMDocument;
                    $newdoc->loadXML($wf_xmlString);
                    $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                    $node = DH::findFirstElementByNameAttr("entry", $name . "-WF", $node);
                    $node = $newdoc->importNode($node, TRUE);
                    $node = $ownerDocument->importNode($node, TRUE);
                    $wf->load_from_domxml($node);
                    $wf->owner = null;
                    $store->addSecurityProfile($wf);

                    if( $context->isAPI )
                        $wf->API_sync();
                }

                $secprofgrp = $sharedStore->securityProfileGroupStore->find($name);
                if( $secprofgrp === null )
                {
                    $secprofgrp = new SecurityProfileGroup($name, $sharedStore->securityProfileGroupStore, TRUE);

                    $secprofgrp->setSecProf_AV($av->name());
                    $secprofgrp->setSecProf_Spyware($as->name());
                    $secprofgrp->setSecProf_Vuln($vp->name());
                    $secprofgrp->setSecProf_URL($url->name());
                    $secprofgrp->setSecProf_FileBlock($fb->name());
                    $secprofgrp->setSecProf_Wildfire($wf->name());


                    $sharedStore->securityProfileGroupStore->addSecurityProfileGroup($secprofgrp);

                    if( $context->isAPI )
                        $secprofgrp->API_sync();
                }

                
                $context->first = false;
            }
        }
    },
    'args' => array(
        'shared' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; securityProfiles are create at SHARED level; at least one DG must be available"
        )
    )
);


DeviceCallContext::$supportedActions['sp_spg-create-BP'] = array(
    'name' => 'sp_spg-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        if( $context->subSystem->isPanorama() )
        {
            $countDG = count( $context->subSystem->getDeviceGroups() );
            if( $countDG == 0  )
            {
                #$dg = $context->subSystem->createDeviceGroup( "alert-only" );
                derr( "NO DG available; please run 'pa_device-edit in=InputConfig.xml out=OutputConfig.xml actions=devicegroup-create:DG-NAME' first", null, false );
            }
        }
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $pathString = dirname(__FILE__)."/../../iron-skillet";
            $av_xmlString_v8 = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_virus.xml");
            $av_xmlString_v9 = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_virus.xml");
            $av_xmlString_v10 = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_virus.xml");

            $as_xmlString_v8 = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_spyware.xml");
            $as_xmlString_v9 = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_spyware.xml");
            $as_xmlString_v10 = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_spyware.xml");

            $vp_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_vulnerability.xml");

            $url_xmlString_v8 = file_get_contents( $pathString."/panos_v8.1/templates/panorama/snippets/profiles_url_filtering.xml");
            $url_xmlString_v9 = file_get_contents( $pathString."/panos_v9.1/templates/panorama/snippets/profiles_url_filtering.xml");
            $url_xmlString_v10 = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_url_filtering.xml");

            $fb_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_file_blocking.xml");

            $wf_xmlString = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/profiles_wildfire_analysis.xml");

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $context->arguments['shared'] && !$context->subSystem->isFirewall() )
                    $sharedStore = $sub->owner;
                else
                    $sharedStore = $sub;


                $ownerDocument = $sub->xmlroot->ownerDocument;

                $force = false; // check about actions argument introduction
                if( isset($context->arguments['sp-name']) )
                    $nameArray = array("Outbound");
                else
                    $nameArray = array("Alert-Only", "Outbound", "Inbound", "Internal", "Exception");


                foreach( $nameArray as $name)
                {
                    if( isset($context->arguments['sp-name']) )
                    {
                        $ironskilletName = $name;
                        $name = $context->arguments['sp-name'];
                    }
                    else
                        $ironskilletName = $name;


                    if( $context->object->owner->version < 90 )
                        $customURLarray = array("Black-List", "White-List", "Custom-No-Decrypt");
                    else
                        $customURLarray = array("Block", "Allow", "Custom-No-Decrypt");
                    foreach( $customURLarray as $entry )
                    {
                        $block = $sharedStore->customURLProfileStore->find($entry);
                        if( $block === null )
                        {
                            $block = $sharedStore->customURLProfileStore->newCustomSecurityProfileURL($entry);
                            if( $context->isAPI )
                                $block->API_sync();
                        }
                    }


                    $av = $sharedStore->AntiVirusProfileStore->find($name . "-AV");
                    if( $av === null )
                    {
                        $store = $sharedStore->AntiVirusProfileStore;
                        $av = new AntiVirusProfile($name . "-AV", $store);
                        $newdoc = new DOMDocument;
                        if( $context->object->owner->version < 90 )
                            $newdoc->loadXML($av_xmlString_v8);
                        elseif( $context->object->owner->version < 100 )
                            $newdoc->loadXML($av_xmlString_v9);
                        else
                            $newdoc->loadXML($av_xmlString_v10);
                        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                        $node = DH::findFirstElementByNameAttr("entry", $ironskilletName . "-AV", $node);
                        if( $node !== null && $node->hasChildNodes() )
                        {
                            $node = $ownerDocument->importNode($node, TRUE);
                            $av->load_from_domxml($node);
                            $av->owner = null;
                            if( isset($context->arguments['sp-name']) )
                                $av->setName( $name."-AV");
                            $store->addSecurityProfile($av);

                            if( $context->isAPI )
                                $av->API_sync();
                        }
                        else
                        {
                            $store->removeSecurityProfile( $av );
                            $av = null;
                        }
                    }

                    $as = $sharedStore->AntiSpywareProfileStore->find($name . "-AS");
                    if( $as === null )
                    {
                        $store = $sharedStore->AntiSpywareProfileStore;
                        $as = new AntiSpywareProfile($name . "-AS", $store);
                        $newdoc = new DOMDocument;
                        if( $context->object->owner->version < 90 )
                            $newdoc->loadXML($as_xmlString_v8);
                        elseif( $context->object->owner->version < 100 )
                            $newdoc->loadXML($as_xmlString_v9);
                        else
                            $newdoc->loadXML($as_xmlString_v10);
                        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                        $node = DH::findFirstElementByNameAttr("entry", $ironskilletName . "-AS", $node);
                        if( $node !== null && $node->hasChildNodes() )
                        {
                            $node = $newdoc->importNode($node, TRUE);
                            $node = $ownerDocument->importNode($node, TRUE);
                            $as->load_from_domxml($node);
                            $as->owner = null;
                            if( isset($context->arguments['sp-name']) )
                                $as->setName( $name."-AS");
                            $store->addSecurityProfile($as);

                            if( $context->isAPI )
                                $as->API_sync();
                        }
                        else
                        {
                            $store->removeSecurityProfile( $as );
                            $as = null;
                        }
                    }

                    $vp = $sharedStore->VulnerabilityProfileStore->find($name . "-VP");
                    if( $vp === null )
                    {
                        $store = $sharedStore->VulnerabilityProfileStore;
                        $vp = new VulnerabilityProfile($name . "-VP", $store);
                        $newdoc = new DOMDocument;
                        $newdoc->loadXML($vp_xmlString);
                        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                        $node = DH::findFirstElementByNameAttr("entry", $ironskilletName . "-VP", $node);
                        if( $node !== null && $node->hasChildNodes() )
                        {
                            $node = $newdoc->importNode($node, TRUE);
                            $node = $ownerDocument->importNode($node, TRUE);
                            $vp->load_from_domxml($node);
                            $vp->owner = null;
                            if( isset($context->arguments['sp-name']) )
                                $vp->setName( $name."-VP");
                            $store->addSecurityProfile($vp);

                            if( $context->isAPI )
                                $vp->API_sync();
                        }
                        else
                        {
                            $store->removeSecurityProfile( $vp );
                            $vp = null;
                        }
                    }

                    $url = $sharedStore->URLProfileStore->find($name . "-URL");
                    if( $url === null )
                    {
                        $store = $sharedStore->URLProfileStore;
                        $url = new URLProfile($name . "-URL", $store);
                        $newdoc = new DOMDocument;
                        if( $context->object->owner->version < 90 )
                            $newdoc->loadXML($url_xmlString_v8);
                        elseif( $context->object->owner->version < 100 )
                            $newdoc->loadXML($url_xmlString_v9);
                        else
                            $newdoc->loadXML($url_xmlString_v10);
                        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                        $node = DH::findFirstElementByNameAttr("entry", $ironskilletName . "-URL", $node);
                        if( $node !== null && $node->hasChildNodes() )
                        {
                            $node = $newdoc->importNode($node, TRUE);
                            $node = $ownerDocument->importNode($node, TRUE);
                            $url->load_from_domxml($node);
                            $url->owner = null;
                            if( isset($context->arguments['sp-name']) )
                                $url->setName( $name."-URL");
                            $store->addSecurityProfile($url);

                            if( $context->isAPI )
                                $url->API_sync();
                        }
                        else
                        {
                            $store->removeSecurityProfile( $url );
                            $url = null;
                        }
                    }

                    $fb = $sharedStore->FileBlockingProfileStore->find($name . "-FB");
                    if( $fb === null )
                    {
                        $store = $sharedStore->FileBlockingProfileStore;
                        $fb = new FileBlockingProfile($name . "-FB", $store);
                        $newdoc = new DOMDocument;
                        $newdoc->loadXML($fb_xmlString);
                        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                        $node = DH::findFirstElementByNameAttr("entry", $ironskilletName . "-FB", $node);
                        if( $node !== null && $node->hasChildNodes() )
                        {
                            $node = $newdoc->importNode($node, TRUE);
                            $node = $ownerDocument->importNode($node, TRUE);
                            $fb->load_from_domxml($node);
                            $fb->owner = null;
                            if( isset($context->arguments['sp-name']) )
                                $fb->setName( $name."-FB");
                            $store->addSecurityProfile($fb);

                            if( $context->isAPI )
                                $fb->API_sync();
                        }
                        else
                        {
                            $store->removeSecurityProfile( $fb );
                            $fb = null;
                        }
                    }

                    $wf = $sharedStore->WildfireProfileStore->find($name . "-WF");
                    if( $wf === null )
                    {
                        $store = $sharedStore->WildfireProfileStore;
                        $wf = new WildfireProfile($name . "-WF", $store);
                        $newdoc = new DOMDocument;
                        $newdoc->loadXML($wf_xmlString);
                        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                        $node = DH::findFirstElementByNameAttr("entry", $ironskilletName . "-WF", $node);
                        if( $node !== null && $node->hasChildNodes() )
                        {
                            $node = $newdoc->importNode($node, TRUE);
                            $node = $ownerDocument->importNode($node, TRUE);
                            $wf->load_from_domxml($node);
                            $wf->owner = null;
                            if( isset($context->arguments['sp-name']) )
                                $wf->setName( $name."-WF");
                            $store->addSecurityProfile($wf);

                            if( $context->isAPI )
                                $wf->API_sync();
                        }
                        else
                        {
                            $store->removeSecurityProfile( $wf );
                            $wf = null;
                        }
                    }

                    $secprofgrp = $sharedStore->securityProfileGroupStore->find($name);
                    if( $secprofgrp === null )
                    {
                        $secprofgrp = new SecurityProfileGroup($name, $sharedStore->securityProfileGroupStore, TRUE);

                        if( $av !== null )
                            $secprofgrp->setSecProf_AV($av->name());
                        if( $as !== null )
                            $secprofgrp->setSecProf_Spyware($as->name());
                        if( $vp !== null )
                            $secprofgrp->setSecProf_Vuln($vp->name());
                        if( $url !== null )
                            $secprofgrp->setSecProf_URL($url->name());
                        if( $fb !== null )
                            $secprofgrp->setSecProf_FileBlock($fb->name());
                        if( $wf !== null )
                            $secprofgrp->setSecProf_Wildfire($wf->name());


                        $sharedStore->securityProfileGroupStore->addSecurityProfileGroup($secprofgrp);

                        if( $context->isAPI )
                            $secprofgrp->API_sync();
                    }
                }

                $context->first = false;
            }
        }
    },
    'args' => array(
        'shared' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; securityProfiles are create at SHARED level; at least one DG must be available"
        ),
        'sp-name' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "if set, only ironskillet SP called 'Outbound' are created with the name defined"
        )
    )
);

DeviceCallContext::$supportedActions['LogForwardingProfile-create-BP'] = array(
    'name' => 'logforwardingprofile-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;

        if( $context->subSystem->isPanorama() )
        {
            $countDG = count( $context->subSystem->getDeviceGroups() );
            if( $countDG == 0 )
            {
                #$dg = $context->subSystem->createDeviceGroup( "alert-only" );
                derr( "NO DG available; please run 'pa_device-edit in=InputConfig.xml out=OutputConfig.xml actions=devicegroup-create:DG-NAME' first", null, false );
            }
        }
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $pathString = dirname(__FILE__)."/../../iron-skillet";
            $lfp_bp_xmlstring = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/log_settings_profiles.xml");

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $context->arguments['shared'] || $context->subSystem->isFirewall() )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);
                }
                else
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;
                }

                $ownerDocument = $sub->xmlroot->ownerDocument;

                $newdoc = new DOMDocument;
                $newdoc->loadXML( $lfp_bp_xmlstring );
                $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                $node = DH::findFirstElementByNameAttr( "entry", "default", $node );
                $node = $ownerDocument->importNode($node, TRUE);


                $logSettings = DH::findFirstElementOrCreate('log-settings', $xmlRoot);
                $logSettingProfiles = DH::findFirstElementOrCreate('profiles', $logSettings);

                $entryDefault = DH::findFirstElementByNameAttr( 'entry', 'default', $logSettingProfiles );


                if( $entryDefault === null )
                {
                    $logSettingProfiles->appendChild( $node );

                    if( $context->isAPI )
                    {
                        $entryDefault_xmlroot = DH::findFirstElementByNameAttr( 'entry', 'default', $logSettingProfiles );

                        $xpath = DH::elementToPanXPath($logSettingProfiles);
                        $con = findConnectorOrDie($object);

                        $getXmlText_inline = DH::dom_to_xml($entryDefault_xmlroot, -1, FALSE);
                        $con->sendSetRequest($xpath, $getXmlText_inline);
                    }
                }
                else
                {
                    $string = "LogForwardingProfile 'default' already available. BestPractise LogForwardingProfile 'default' not created";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                }



                $context->first = false;
            }
        }
    },
    'args' => array(
        'shared' => array('type' => 'bool', 'default' => 'false',
            'help' => "if set to true; LogForwardingProfile is create at SHARED level; at least one DG must be available"
        )
    )
);

DeviceCallContext::$supportedActions['ZoneProtectionProfile-create-BP'] = array(
    'name' => 'zoneprotectionprofile-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context)
    {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $pathString = dirname(__FILE__)."/../../iron-skillet";
            $zpp_bp_xmlstring = file_get_contents( $pathString."/panos_v10.0/templates/panorama/snippets/zone_protection_profile.xml");

            if( $classtype == "VirtualSystem" || $classtype == "Template" )
            {
                $sub = $object;

                $sharedStore = $sub;
                if( $classtype == "Template" )
                {
                    $xmlRoot = $sharedStore->deviceConfiguration->network->xmlroot;
                    if( $xmlRoot === null )
                    {
                        $xmlRoot = DH::findFirstElementOrCreate('devices', $sharedStore->deviceConfiguration->xmlroot);

                        #$xmlRoot = DH::findFirstElementByNameAttrOrCreate( 'entry', 'localhost.localdomain', $xmlRoot, $sharedStore->deviceConfiguration->xmlroot->ownerDocument);
                        $xmlRoot = DH::findFirstElementOrCreate('entry', $xmlRoot);
                        $xmlRoot->setAttribute( "name", 'localhost.localdomain' );
                        $xmlRoot = DH::findFirstElementOrCreate('network', $xmlRoot);
                    }
                }
                elseif( $classtype == "VirtualSystem" )
                {
                    $xmlRoot = $sharedStore->owner->network->xmlroot;
                    if( $xmlRoot === null )
                    {
                        $xmlRoot = DH::findFirstElementOrCreate('devices', $sharedStore->owner->xmlroot);

                        #$xmlRoot = DH::findFirstElementByNameAttrOrCreate( 'entry', 'localhost.localdomain', $xmlRoot, $sharedStore->owner->xmlroot->ownerDocument);
                        $xmlRoot = DH::findFirstElementOrCreate('entry', $xmlRoot);
                        $xmlRoot->setAttribute( "name", 'localhost.localdomain' );
                        $xmlRoot = DH::findFirstElementOrCreate('network', $xmlRoot);
                    }
                }


                $ownerDocument = $sub->xmlroot->ownerDocument;

                $newdoc = new DOMDocument;
                $newdoc->loadXML( $zpp_bp_xmlstring );
                $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                $node = DH::findFirstElementByNameAttr( "entry", "Recommended_Zone_Protection", $node );
                $node = $ownerDocument->importNode($node, TRUE);


                $networkProfiles = DH::findFirstElementOrCreate('profiles', $xmlRoot);
                $zppXMLroot = DH::findFirstElementOrCreate('zone-protection-profile', $networkProfiles);

                $entryDefault = DH::findFirstElementByNameAttr( 'entry', 'Recommended_Zone_Protection', $zppXMLroot );


                if( $entryDefault === null )
                {
                    $zppXMLroot->appendChild( $node );

                    if( $context->isAPI )
                    {
                        $entryDefault_xmlroot = DH::findFirstElementByNameAttr( 'entry', 'Recommended_Zone_Protection', $zppXMLroot );

                        $xpath = DH::elementToPanXPath($zppXMLroot);
                        $con = findConnectorOrDie($object);

                        $getXmlText_inline = DH::dom_to_xml($entryDefault_xmlroot, -1, FALSE);
                        $con->sendSetRequest($xpath, $getXmlText_inline);
                    }
                }

                else
                {
                    $string = "ZoneProtectionProfile 'Recommended_Zone_Protection' already available. BestPractise ZoneProtectionProfile 'Recommended_Zone_Protection' not created";
                    PH::ACTIONstatus( $context, "SKIPPED", $string );
                }


                //create for all VSYS and all templates
                #$context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['CleanUpRule-create-BP'] = array(
    'name' => 'cleanuprule-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $context->arguments['logprof'] )
                $logprof = $context->arguments['logprof'];
            else
                $logprof = "default";

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                $skip = false;
                if( $classtype == "VirtualSystem" )
                {
                    //create security Rule at end
                    $name = "CleanupRule-BP";
                    $cleanupRule = $sub->securityRules->find( $name );
                    if( $cleanupRule === null )
                        $cleanupRule = $sub->securityRules->newSecurityRule( $name );
                    else
                        $skip = true;
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;

                    //create security Rule at end
                    $name = "CleanupRule-BP";
                    $cleanupRule = $sharedStore->securityRules->find( $name );
                    if( $cleanupRule === null )
                        $cleanupRule = $sharedStore->securityRules->newSecurityRule("CleanupRule-BP", true);
                    else
                        $skip = true;
                }

                if( !$skip )
                {
                    $cleanupRule->source->setAny();
                    $cleanupRule->destination->setAny();
                    $cleanupRule->services->setAny();
                    $cleanupRule->setAction( 'deny');
                    $cleanupRule->setLogStart( false );
                    $cleanupRule->setLogEnd( true );
                    $cleanupRule->setLogSetting( $logprof );
                    if( $context->isAPI )
                        $cleanupRule->API_sync();
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
    'logprof' => array('type' => 'string', 'default' => 'default',
        'help' => "LogForwardingProfile name"
    )
)
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-create-BP'] = array(
    'name' => 'defaultsecurityRule-create-bp',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $context->arguments['logprof'] )
                $logprof = $context->arguments['logprof'];
            else
                $logprof = "default";

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rulebase->removeChild( $defaultSecurityRules );

                $defaultSecurityRules_xml = "<default-security-rules>
                    <rules>
                      <entry name=\"intrazone-default\">
                        <action>deny</action>
                        <log-start>no</log-start>
                        <log-end>yes</log-end>
                        <log-setting>".$logprof."</log-setting>
                      </entry>
                      <entry name=\"interzone-default\">
                        <action>deny</action>
                        <log-start>no</log-start>
                        <log-end>yes</log-end>
                        <log-setting>".$logprof."</log-setting>
                      </entry>
                    </rules>
                  </default-security-rules>";

                $ownerDocument = $sub->xmlroot->ownerDocument;

                $newdoc = new DOMDocument;
                $newdoc->loadXML( $defaultSecurityRules_xml );
                $node = $newdoc->importNode($newdoc->firstChild, TRUE);
                $node = $ownerDocument->importNode($node, TRUE);
                $rulebase->appendChild( $node );

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'logprof' => array('type' => 'string', 'default' => 'default',
            'help' => "LogForwardingProfile name"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-logend-enable'] = array(
    'name' => 'defaultsecurityrule-logend-enable',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );
                    $logend = DH::findFirstElementOrCreate( "log-end", $tmp_XYZzone_xml );

                    $logend->textContent = "yes";

                    $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $action === FALSE )
                    {
                        if( $entry === "intrazone-default" )
                            $action_txt = "allow";
                        elseif( $entry === "interzone-default" )
                            $action_txt = "deny";

                        $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $action->textContent = $action_txt;
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-logstart-disable'] = array(
    'name' => 'defaultsecurityrule-logstart-disable',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );

                    $logstart = DH::findFirstElementOrCreate( "log-start", $tmp_XYZzone_xml );
                    $logstart->textContent = "no";

                    $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $action === FALSE )
                    {
                        if( $entry === "intrazone-default" )
                            $action_txt = "allow";
                        elseif( $entry === "interzone-default" )
                            $action_txt = "deny";

                        $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $action->textContent = $action_txt;
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-logsetting-set'] = array(
    'name' => 'defaultsecurityrule-logsetting-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $context->arguments['logprof'] )
                $logprof = $context->arguments['logprof'];
            else
                $logprof = "default";

            $force = $context->arguments['force'];

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );

                    $logsetting = DH::findFirstElement( "log-setting", $tmp_XYZzone_xml );
                    if( $logsetting !== FALSE || $force )
                    {
                        if( $force )
                            $logsetting->textContent = $logprof;
                    }
                    else
                    {
                        $logsetting = DH::findFirstElementOrCreate( "log-setting", $tmp_XYZzone_xml );
                        $logsetting->textContent = $logprof;
                    }

                    $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $action === FALSE )
                    {
                        if( $entry === "intrazone-default" )
                            $action_txt = "allow";
                        elseif( $entry === "interzone-default" )
                            $action_txt = "deny";

                        $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $action->textContent = $action_txt;
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'logprof' => array('type' => 'string', 'default' => 'default',
            'help' => "LogForwardingProfile name"
        ),
        'force' => array('type' => 'bool', 'default' => 'false',
            'help' => "LogForwardingProfile overwrite"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-remove-override'] = array(
    'name' => 'defaultsecurityrule-remove-override',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules !== FALSE )
                    $rulebase->removeChild( $defaultSecurityRules );
                else
                    return;

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules_xmlroot !== FALSE )
                    {
                        $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                        $con = findConnectorOrDie($object);

                        $con->sendDeleteRequest( $xpath );
                    }
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-securityProfile-Remove'] = array(
    'name' => 'defaultsecurityrule-securityprofile-remove',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $force = $context->arguments['force'];

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules === FALSE )
                    return;

                $rules = DH::findFirstElement( "rules", $defaultSecurityRules );
                if( $rules === FALSE )
                    return;

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules );
                    if( $tmp_XYZzone_xml !== null )
                    {
                        $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                        if( $action === FALSE )
                        {
                            if( $entry === "intrazone-default" )
                                $action_txt = "allow";
                            elseif( $entry === "interzone-default" )
                                $action_txt = "deny";
                        }
                        else
                            $action_txt = $action->textContent;

                        if( $action_txt !== "allow" || $force )
                        {
                            $profilesetting = DH::findFirstElement( "profile-setting", $tmp_XYZzone_xml );
                            if( $profilesetting !== FALSE )
                                $tmp_XYZzone_xml->removeChild( $profilesetting );
                        }
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElement( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules === FALSE )
                        return;

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'force' => array('type' => 'bool', 'default' => 'false',
            'help' => "per default, remove SecurityProfiles only if Rule action is NOT allow. force=true => remove always"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-SecurityProfileGroup-Set'] = array(
    'name' => 'defaultsecurityrule-securityprofilegroup-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->first )
        {
            $secProfGroup = $context->arguments['securityProfileGroup'];



            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                //validation, if this group name is available in the relevant store or above
                $tmp_secgroup = $sub->securityProfileGroupStore->find( $secProfGroup );
                if( $tmp_secgroup === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfileGroup name: ".$secProfGroup." not found!" );
                    return;
                }

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules === FALSE )
                    return;

                $rules = DH::findFirstElement( "rules", $defaultSecurityRules );
                if( $rules === FALSE )
                    return;

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules );
                    if( $tmp_XYZzone_xml !== null )
                    {
                        $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                        if( $action === FALSE )
                        {
                            if( $entry === "intrazone-default" )
                                $action_txt = "allow";
                            elseif( $entry === "interzone-default" )
                                $action_txt = "deny";
                        }
                        else
                            $action_txt = $action->textContent;

                        if( $action_txt == "allow")
                        {
                            $profilesetting = DH::findFirstElement( "profile-setting", $tmp_XYZzone_xml );

                            if( $profilesetting === false )
                                $profilesetting = DH::findFirstElementOrCreate( "profile-setting", $tmp_XYZzone_xml );
                            else
                            {
                                $tmp_XYZzone_xml->removeChild( $profilesetting );
                                $profilesetting = DH::findFirstElementOrCreate( "profile-setting", $tmp_XYZzone_xml );
                            }

                            $group = DH::findFirstElementOrCreate( "group", $profilesetting );
                            $tmp = DH::findFirstElementOrCreate( "member", $group );

                            $tmp->textContent = $secProfGroup;
                        }
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElement( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules === FALSE )
                        return;

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'securityProfileGroup' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "set SecurityProfileGroup to default SecurityRules, if the Rule is an allow rule"
        )
    )
);

DeviceCallContext::$supportedActions['DefaultSecurityRule-SecurityProfile-SetAlert'] = array(
    'name' => 'defaultsecurityrule-securityprofile-setAlert',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        $force = $context->arguments['force'];

        if( $context->first )
        {
            $secProfGroup = "Alert-Only";

            $secProf = array();
            $secProf['VP'] = "Alert-Only-VP";
            $secProf['AS'] = "Alert-Only-AS";
            $secProf['AV'] = "Alert-Only-AV";
            $secProf['URL'] = "Alert-Only-URL";
            $secProf['FB'] = "Alert-Only-FB";
            $secProf['WF'] = "Alert-Only-WF";

            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                /** @var VirtualSystem|DeviceGroup $sub */
                $sub = $object;

                //validation, if this group name is available in the relevant store or above
                $tmp_secgroup = $sub->securityProfileGroupStore->find( $secProfGroup );
                if( $tmp_secgroup === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfileGroup name: ".$secProfGroup." not found!" );
                    return;
                }
                $tmp_secprof = $sub->VulnerabilityProfileStore->find( $secProf['VP'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile VP name: ".$secProf['VP']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->AntiSpywareProfileStore->find( $secProf['AS'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile AS name: ".$secProf['AS']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->AntiVirusProfileStore->find( $secProf['AV'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile AV name: ".$secProf['AV']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->URLProfileStore->find( $secProf['URL'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile URL name: ".$secProf['URL']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->FileBlockingProfileStore->find( $secProf['FB'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile FB name: ".$secProf['FB']." not found!" );
                    return;
                }
                $tmp_secprof = $sub->WildfireProfileStore->find( $secProf['WF'] );
                if( $tmp_secprof === null )
                {
                    PH::ACTIONstatus($context, "skipped", "SecurityProfile WF name: ".$secProf['WF']." not found!" );
                    return;
                }


                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElement( "default-security-rules", $rulebase );
                if( $defaultSecurityRules === FALSE )
                    return;

                $rules = DH::findFirstElement( "rules", $defaultSecurityRules );
                if( $rules === FALSE )
                    return;

                $array = array( "intrazone-default", "interzone-default" );
                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules );
                    if( $tmp_XYZzone_xml !== null )
                    {
                        $action = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                        if( $action === FALSE )
                        {
                            if( $entry === "intrazone-default" )
                                $action_txt = "allow";
                            elseif( $entry === "interzone-default" )
                                $action_txt = "deny";
                        }
                        else
                            $action_txt = $action->textContent;

                        if( $action_txt == "allow")
                        {
                            $profilesetting = DH::findFirstElement( "profile-setting", $tmp_XYZzone_xml );

                            if( $profilesetting === false )
                            {
                                $profilesetting = DH::findFirstElementOrCreate( "profile-setting", $tmp_XYZzone_xml );
                                $group = DH::findFirstElementOrCreate( "group", $profilesetting );
                                $tmp = DH::findFirstElementOrCreate( "member", $group );

                                $tmp->textContent = $secProfGroup;
                            }

                            else
                            {
                                $profiles = DH::findFirstElement( "profiles", $profilesetting );
                                if( $profiles !== false )
                                {
                                    $seprof = DH::findFirstElement( "url-filtering", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "url-filtering", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['URL'];
                                    }
                                    $seprof = DH::findFirstElement( "file-blocking", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "file-blocking", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['FB'];
                                    }
                                    $seprof = DH::findFirstElement( "virus", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "virus", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['AV'];
                                    }
                                    $seprof = DH::findFirstElement( "spyware", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "spyware", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['AS'];
                                    }
                                    $seprof = DH::findFirstElement( "vulnerability", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "vulnerability", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['VP'];
                                    }
                                    $seprof = DH::findFirstElement( "wildfire-analysis", $profiles );
                                    if( $seprof === false )
                                    {
                                        $seprof = DH::findFirstElementOrCreate( "wildfire-analysis", $profiles );
                                        $tmp = DH::findFirstElementOrCreate( "member", $seprof );
                                        if( $tmp->textContent === "" || $tmp->textContent === "None" || $tmp->textContent === "none" )
                                            $tmp->textContent = $secProf['WF'];
                                    }
                                }
                            }
                        }
                    }
                }

                if( $context->isAPI )
                {
                    $defaultSecurityRules_xmlroot = DH::findFirstElement( "default-security-rules", $rulebase );
                    if( $defaultSecurityRules === FALSE )
                        return;

                    $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                    $con = findConnectorOrDie($object);

                    $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                    $con->sendEditRequest($xpath, $getXmlText_inline);
                }

                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    }
);


DeviceCallContext::$supportedActions['DefaultSecurityRule-action-set'] = array(
    'name' => 'defaultsecurityrule-action-set',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        $context->first = true;
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $object = $context->object;
        $classtype = get_class($object);

        if( $context->arguments['ruletype'] )
            $ruletype = $context->arguments['ruletype'];

        if( $context->arguments['action'] )
            $action = $context->arguments['action'];

        if( $ruletype !== 'intrazone' && $ruletype !== 'interzone' && $ruletype !== 'all' )
        {
            $string ="only ruletype 'intrazone'|'interzone'|'all' is allowed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }
        else
            $ruletype .= "-default";

        if( $action !== 'allow' && $action !== 'deny' )
        {
            $string = "only action 'allow' or 'deny' is allowed";
            PH::ACTIONstatus( $context, "SKIPPED", $string );
            return;
        }

        if( $context->first )
        {
            if( $classtype == "VirtualSystem" || $classtype == "DeviceGroup" )
            {
                $sub = $object;

                if( $classtype == "VirtualSystem" )
                {
                    $sharedStore = $sub;
                    $xmlRoot = $sharedStore->xmlroot;

                    $rulebase = DH::findFirstElementOrCreate( "rulebase", $xmlRoot );
                }
                elseif( $classtype == "DeviceGroup" )
                {
                    $sharedStore = $sub->owner;
                    $xmlRoot = DH::findFirstElementOrCreate('shared', $sharedStore->xmlroot);

                    $rulebase = DH::findFirstElementOrCreate( "post-rulebase", $xmlRoot );
                }

                $defaultSecurityRules = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                $rules = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules );

                if( $ruletype === 'all-default' )
                    $array = array( "intrazone-default", "interzone-default" );
                else
                    $array = array( $ruletype );

                foreach( $array as $entry)
                {
                    $tmp_XYZzone_xml = DH::findFirstElementByNameAttrOrCreate( "entry", $entry, $rules, $sharedStore->xmlroot->ownerDocument );

                    if( $entry === "intrazone-default" )
                        $action_txt = $action;
                    elseif( $entry === "interzone-default" )
                        $action_txt = $action;

                    /*
                    if( $entry === "intrazone-default" && $action === "allow" )
                    {
                        $string = "ruletype: intrazone-default and action:allow - is default value";
                        PH::ACTIONstatus( $context, "SKIPPED", $string );
                        return;
                    }
                    */


                    $xmlAction = DH::findFirstElement( "action", $tmp_XYZzone_xml );
                    if( $xmlAction !== FALSE )
                    {
                        if( $xmlAction->textContent !== $action_txt )
                        {
                            $action = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                            $xmlAction->nodeValue = $action_txt;
                        }
                    }
                    else
                    {
                        $xmlAction = DH::findFirstElementOrCreate( "action", $tmp_XYZzone_xml );
                        $xmlAction->nodeValue = $action_txt;
                    }



                    if( $context->isAPI )
                    {
                        $defaultSecurityRules_xmlroot = DH::findFirstElementOrCreate( "default-security-rules", $rulebase );
                        $rules_zml = DH::findFirstElementOrCreate( "rules", $defaultSecurityRules_xmlroot );
                        $tmp_XYZzone_xml = DH::findFirstElementByNameAttr( "entry", $entry, $rules_zml, $sharedStore->xmlroot->ownerDocument );

                        $xpath = DH::elementToPanXPath($defaultSecurityRules_xmlroot);
                        $con = findConnectorOrDie($object);

                        $getXmlText_inline = DH::dom_to_xml($defaultSecurityRules_xmlroot, -1, FALSE);
                        $con->sendEditRequest($xpath, $getXmlText_inline);
                    }

                }



                if( $classtype == "DeviceGroup" )
                    $context->first = false;
            }
        }
    },
    'args' => array(
        'ruletype' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "define which ruletype; 'intrazone'|'interzone'|'all' "
        ),
        'action' => array('type' => 'string', 'default' => '*nodefault*',
            'help' => "define the action you like to set 'allow'|'deny'"
        )
    )
);


DeviceCallContext::$supportedActions['find-zone-from-ip'] = array(
    'name' => 'find-zone-from-ip',
    'GlobalInitFunction' => function (DeviceCallContext $context) {
        //
    },
    'MainFunction' => function (DeviceCallContext $context) {
        $device = $context->object;

        if( get_class( $device ) !== "VirtualSystem" && get_class( $device ) !== "ManagedDevice" )
        {
            print get_class( $device )."\n";
            derr( "not of type 'VirtualSystem' / 'ManagedDevice', not supporedted" );
        }

        $zoneContainer = new ZoneRuleContainer( null );
        $system = $device;
        $configIsOnLocalFirewall = FALSE;
        if( get_class( $device ) == "VirtualSystem" )
        {
            $zones = $device->zoneStore->getAll();
            foreach( $zones as $zone )
            {
                #print "add Zone: ".$zone->name()."\n";
                $zoneContainer->addZone( $zone, false );
            }
        }

        elseif( get_class( $device ) == "ManagedDevice" )
        {
            $configIsOnLocalFirewall = TRUE;
            $context->arguments['template'] = "api@".$device->name();
        }

        $ip_address = $context->arguments['ip'];


        $ip = new Address( $ip_address, null );
        $ip->setType( "ip-netmask", false);
        $ip->setValue( $ip_address, false );

        $addressContainer = new AddressRuleContainer( null );
        $addressContainer->addObject( $ip );




        /** @var VirtualRouter $virtualRouterToProcess */
        $virtualRouterToProcess = null;

        if( !isset($context->cachedIPmapping) )
            $context->cachedIPmapping = array();

        $serial = spl_object_hash($device->owner);


        if( !isset($context->cachedIPmapping[$serial]) )
        {
            if( $system->isDeviceGroup() || $system->isPanorama() || $system->isManagedDevice() )
            {
                $firewall = null;
                $panorama = $system;
                if( $system->isDeviceGroup() )
                    $panorama = $system->owner;

                if( $context->arguments['template'] == $context->actionRef['args']['template']['default'] )
                    derr('with Panorama configs, you need to specify a template name');

                if( !$system->isManagedDevice() )
                    if( $context->arguments['virtualRouter'] == $context->actionRef['args']['virtualRouter']['default'] )
                        derr('with Panorama configs, you need to specify virtualRouter argument. Available virtual routes are: ');

                $_tmp_explTemplateName = explode('@', $context->arguments['template']);
                if( count($_tmp_explTemplateName) > 1 )
                {
                    $firewall = new PANConf();
                    $configIsOnLocalFirewall = TRUE;
                    $doc = null;

                    if( strtolower($_tmp_explTemplateName[0]) == 'api' )
                    {
                        $panoramaConnector = findConnector($system);
                        $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                        $firewall->connector = $connector;
                        $doc = $connector->getMergedConfig();
                        $firewall->load_from_domxml($doc);
                        unset($connector);
                    }
                    elseif( strtolower($_tmp_explTemplateName[0]) == 'file' )
                    {
                        $filename = $_tmp_explTemplateName[1];
                        if( !file_exists($filename) )
                            derr("cannot read firewall configuration file '{$filename}''");
                        $doc = new DOMDocument();
                        if( !$doc->load($filename, XML_PARSE_BIG_LINES) )
                            derr("invalive xml file" . libxml_get_last_error()->message);
                        unset($filename);
                    }
                    else
                        derr("unsupported method: {$_tmp_explTemplateName[0]}@");


                    // delete rules to avoid loading all the config
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/devices/entry/vsys/entry/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/shared/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");

                    //PH::print_stdout( "\n\n deleted $deletedNodesCount nodes" );

                    $firewall->load_from_domxml($doc);

                    unset($deletedNodesCount);
                    unset($doc);
                }


                /** @var Template $template */
                if( !$configIsOnLocalFirewall )
                {
                    $template = $panorama->findTemplate($context->arguments['template']);
                    if( $template === null )
                        derr("cannot find Template named '{$context->arguments['template']}'. Available template list:" . PH::list_to_string($panorama->templates));
                }

                if( $configIsOnLocalFirewall )
                    $virtualRouterToProcess = $firewall->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);
                else
                    $virtualRouterToProcess = $template->deviceConfiguration->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);

                if( $virtualRouterToProcess === null )
                {
                    if( $configIsOnLocalFirewall )
                        $tmpVar = $firewall->network->virtualRouterStore->virtualRouters();
                    else
                        $tmpVar = $template->deviceConfiguration->network->virtualRouterStore->virtualRouters();

                    derr("cannot find VirtualRouter named '{$context->arguments['virtualRouter']}' in Template '{$context->arguments['template']}'. Available VR list: " . PH::list_to_string($tmpVar), null, false);
                }

                if( (!$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($firewall->virtualSystems) == 1) )
                {
                    if( $configIsOnLocalFirewall )
                        $system = $firewall->virtualSystems[0];
                    else
                        $system = $template->deviceConfiguration->virtualSystems[0];
                }
                else
                {
                    $vsysConcernedByVR = $virtualRouterToProcess->findConcernedVsys();
                    if( count($vsysConcernedByVR) == 1 )
                    {
                        $system = array_pop($vsysConcernedByVR);
                    }
                    elseif( $context->arguments['vsys'] == '*autodetermine*' )
                    {
                        derr("cannot autodetermine resolution context from Template '{$context->arguments['template']}' VR '{$context->arguments['virtualRouter']}'' , multiple VSYS are available: " . PH::list_to_string($vsysConcernedByVR) . ". Please provide choose a VSYS.");
                    }
                    else
                    {
                        if( $configIsOnLocalFirewall )
                            $vsys = $firewall->findVirtualSystem($context->arguments['vsys']);
                        else
                            $vsys = $template->deviceConfiguration->findVirtualSystem($context->arguments['vsys']);
                        if( $vsys === null )
                            derr("cannot find VSYS '{$context->arguments['vsys']}' in Template '{$context->arguments['template']}'");
                        $system = $vsys;
                    }
                }

                //derr(DH::dom_to_xml($template->deviceConfiguration->xmlroot));
                //$tmpVar = $system->importedInterfaces->interfaces();
                //derr(count($tmpVar)." ".PH::list_to_string($tmpVar));
            }
            else if( $context->arguments['virtualRouter'] != '*autodetermine*' )
            {
                $virtualRouterToProcess = $system->owner->network->virtualRouterStore->findVirtualRouter($context->arguments['virtualRouter']);
                if( $virtualRouterToProcess === null )
                    derr("VirtualRouter named '{$context->arguments['virtualRouter']}' not found");

                #print "router: ".$virtualRouterToProcess->name()."\n";
            }
            else
            {
                $vRouters = $system->owner->network->virtualRouterStore->virtualRouters();
                $foundRouters = array();

                foreach( $vRouters as $router )
                {
                    #print "router: ".$router->name()."\n";
                    foreach( $router->attachedInterfaces->interfaces() as $if )
                    {
                        if( $system->importedInterfaces->hasInterfaceNamed($if->name()) )
                        {
                            $foundRouters[] = $router;
                            break;
                        }
                    }
                }

                $string = "VSYS/DG '{$system->name()}' has interfaces attached to " . count($foundRouters) . " virtual routers";
                PH::ACTIONlog($context, $string);
                if( count($foundRouters) > 1 )
                    derr("more than 1 suitable virtual routers found, please specify one fo the following: " . PH::list_to_string($foundRouters));
                if( count($foundRouters) == 0 )
                    derr("no suitable VirtualRouter found, please force one or check your configuration");

                $virtualRouterToProcess = $foundRouters[0];
            }
            $context->cachedIPmapping[$serial] = $virtualRouterToProcess->getIPtoZoneRouteMapping($system);
        }


        $ipMapping = &$context->cachedIPmapping[$serial];
        #print_r( $ipMapping );

        if( $addressContainer->isAny() )
        {
            $string = "address container is ANY()";
            PH::ACTIONstatus($context, "SKIPPED", $string);
            return;
        }


        $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);

        if( count($resolvedZones) == 0 )
        {
            $string = "no zone resolved (FQDN? IPv6?)";
            PH::ACTIONstatus($context, "WARNING", $string);
            return;
        }

        $padding = "     ";
        foreach( $resolvedZones as $zoneName => $zone )
        {
            if( $device->isManagedDevice() )
                PH::print_stdout( $padding."* Hostname: ".$device->hostname );

            PH::print_stdout( $padding."* Zone: ".$zoneName );


            if( $device->isVirtualSystem() )
            {
                $zone_obj = $device->zoneStore->find( $zoneName );
                $interfaces = $zone_obj->attachedInterfaces->getAll();
                foreach( $interfaces as $interface )
                    $interface->display();
            }
        }


    },
    'args' => array(
        'ip' => array('type' => 'string',
            'default' => '*noDefault*',
            'help' => "Please bring in an IP-Address, to find the corresponding Zone."
        ),
        'virtualRouter' => array('type' => 'string',
            'default' => '*autodetermine*',
            'help' => "Can optionally be provided if script cannot find which virtualRouter it should be using" .
                " (ie: there are several VR in same VSYS)"
        ),
        'template' => array('type' => 'string',
            'default' => '*notPanorama*',
            'help' => "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in" .
                " such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden" .
                " or if you are not using Templates then you will want load firewall config in lieu of specifying a template." .
                " \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to" .
                " calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then" .
                " specify file@/folderXYZ/config.xml."
        ),
        'vsys' => array('type' => 'string',
            'default' => '*autodetermine*',
            'help' => "specify vsys when script cannot autodetermine it or when you when to manually override"
        ),
    ),
    'help' => "This Action will use routing tables to resolve zones. When the program cannot find all parameters by" .
        " itself (like vsys or template name you will have to manually provide them.\n\n" .
        "Usage examples:\n\n" .
        "    - find-zone-from-ip:8.8.8.8\n" .
        "    - find-zone-from-ip:8.8.8.8,vr1\n" .
        "    - find-zone-from-ip:8.8.8.8,vr3,api@0011C890C,vsys1\n" .
        "    - find-zone-from-ip:8.8.8.8,vr5,Datacenter_template\n" .
        "    - find-zone-from-ip:8.8.8.8,vr3,file@firewall.xml,vsys1\n"
);