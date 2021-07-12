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

SecurityProfileGroupCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (SecurityProfileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);



SecurityProfileGroupCallContext::$supportedActions[] = array(
    'name' => 'display',
    'MainFunction' => function (SecurityProfileGroupCallContext $context) {
        $object = $context->object;

        PH::print_stdout( $context->padding . "* " . get_class($object) . " '{$object->name()}' (".count($object->secprofiles )." members)" );
        foreach( $object->secprofiles as $key => $prof )
        {
            if( is_object( $prof ) )
                PH::print_stdout( "          - {$key}  '{$prof->name()}'" );
            else
            {
                //defautl prof is string not an object
                PH::print_stdout( "          - {$key}  '{$prof}'" );
            }
        }

        PH::print_stdout(  "" );
    },
);

SecurityProfileGroupCallContext::$supportedActions[] = array(
    'name' => 'securityProfile-Set',
    'MainFunction' => function (SecurityProfileGroupCallContext $context) {
        $secprofgroup = $context->object;

        $type = $context->arguments['type'];
        $profName = $context->arguments['profName'];


        $ret = TRUE;

        if( $type == 'virus' )
            $ret = $secprofgroup->setSecProf_AV($profName);
        elseif( $type == 'vulnerability' )
            $ret = $secprofgroup->setSecProf_Vuln($profName);
        elseif( $type == 'url-filtering' )
            $ret = $secprofgroup->setSecProf_URL($profName);
        elseif( $type == 'data-filtering' )
            $ret = $secprofgroup->setSecProf_DataFilt($profName);
        elseif( $type == 'file-blocking' )
            $ret = $secprofgroup->setSecProf_FileBlock($profName);
        elseif( $type == 'spyware' )
            $ret = $secprofgroup->setSecProf_Spyware($profName);
        elseif( $type == 'wildfire' )
            $ret = $secprofgroup->setSecProf_Wildfire($profName);
        else
            derr("unsupported profile type '{$type}'");

        if( !$ret )
        {
            echo $context->padding . " * SKIPPED : no change detected\n";
            return;
        }


        if( $context->isAPI )
        {
            $xpath = $secprofgroup->getXPath();
            $con = findConnectorOrDie($secprofgroup);
            $con->sendEditRequest($xpath, DH::dom_to_xml($secprofgroup->xmlroot, -1, FALSE));
        }
        else
            #$secprofgroup->rewriteSecProfXML();
            $secprofgroup->rewriteXML();

    },
    'args' => array('type' => array('type' => 'string', 'default' => '*nodefault*',
        'choices' => array('virus', 'vulnerability', 'url-filtering', 'data-filtering', 'file-blocking', 'spyware', 'wildfire')),
        'profName' => array('type' => 'string', 'default' => '*nodefault*'))
);
SecurityProfileGroupCallContext::$supportedActions[] = array(
    'name' => 'securityProfile-Remove',
    'MainFunction' => function (SecurityProfileGroupCallContext $context) {
        $secprofgroup = $context->object;
        $type = $context->arguments['type'];


        $ret = TRUE;
        $profName = "null";

        if( $type == "any" )
        {
            if( $context->isAPI )
                $secprofgroup->API_removeSecurityProfile();
            else
                $secprofgroup->removeSecurityProfile();
        }
        elseif( $type == 'virus' )
            $ret = $secprofgroup->setSecProf_AV($profName);
        elseif( $type == 'vulnerability' )
            $ret = $secprofgroup->setSecProf_Vuln($profName);
        elseif( $type == 'url-filtering' )
            $ret = $secprofgroup->setSecProf_URL($profName);
        elseif( $type == 'data-filtering' )
            $ret = $secprofgroup->setSecProf_DataFilt($profName);
        elseif( $type == 'file-blocking' )
            $ret = $secprofgroup->setSecProf_FileBlock($profName);
        elseif( $type == 'spyware' )
            $ret = $secprofgroup->setSecProf_Spyware($profName);
        elseif( $type == 'wildfire' )
            $ret = $secprofgroup->setSecProf_Wildfire($profName);
        else
            derr("unsupported profile type '{$type}'");

        if( $type != "any" )
        {
            if( !$ret )
            {
                echo $context->padding . " * SKIPPED : no change detected\n";
                return;
            }


            if( $context->isAPI )
            {
                $xpath = $secprofgroup->getXPath();
                $con = findConnectorOrDie($secprofgroup);
                $con->sendEditRequest($xpath, DH::dom_to_xml($secprofgroup->xmlroot, -1, FALSE));
            }
            else
                #$secprofgroup->rewriteSecProfXML();
                $secprofgroup->rewriteXML();
        }

    },
    'args' => array('type' => array('type' => 'string', 'default' => 'any',
        'choices' => array('any', 'virus', 'vulnerability', 'url-filtering', 'data-filtering', 'file-blocking', 'spyware', 'wildfire'))
    )
);