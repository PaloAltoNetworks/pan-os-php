<?php


trait SRXmisc_functions
{


    /**
     * @param DOMElement $configRoot
     */
    function xml_validation($configRoot)
    {
        foreach( $configRoot->childNodes as $key => $childNode )
        {
            /** @var DOMElement $childNode */
            if( $childNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodename = $childNode->nodeName;

            $array_not_in_focus = array(
                "version",
                "groups",
                "apply-groups",
                "system",
                "chassis",
                #"security",
                #"interfaces", //handled in interface part
                "snmp",
                "forwarding-options",
                "event-options",
                "routing-options",
                "protocols",
                "firewall",
                "applications");

            $array_in_focus = array(
                "logical-systems",
                "interfaces",
                "routing-instances",
                "security",
                "applications"

            );

            if( !in_array($nodename, $array_in_focus) )
            {
                mwarning("found nodename: '" . PH::boldText($nodename) . "' which is not in focus for this migration", null, FALSE);
            }
            else
            {
                print "covered: " . $nodename . "\n";
            }


            #print "|".$tmp_name."|\n";

        }
    }

    function interfaceRename( $interfaceName )
    {
        //if subinterface is .0 remove .0
        $interfaceName = preg_replace('/\.0$/', '', $interfaceName);

        if( preg_match("/^ae/", $interfaceName) )
        {
            $tmp_name_org = explode(".", $interfaceName);
            $tmp_name = explode("ae", $tmp_name_org[0]);
            $tmp_counter = intval($tmp_name[1]) + 1;
            if( empty( $tmp_name_org[1] ) )
                $interfaceName = "ae" . $tmp_counter;
            else
                $interfaceName = "ae" . $tmp_counter.".".$tmp_name_org[1];
        }

        return $interfaceName;
    }
}