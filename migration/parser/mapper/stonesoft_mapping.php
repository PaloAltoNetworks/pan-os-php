<?php




function stonesoft_checkfile( $fileName, &$firewalls, &$policy, &$mapping )
{
    global $expedition;

    $stonesoft = file_get_contents($fileName);

    $doc = new DOMDocument();
    $doc->loadXML($stonesoft, XML_PARSE_BIG_LINES);


    $granted_policy_ref = $doc->getElementsByTagName('granted_policy_ref');
#$granted_policy_ref = $granted_policy_ref[0];

    foreach( $granted_policy_ref as $granted_policy  )
    {
        if( $granted_policy !== null )
        {
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($granted_policy, TRUE);
            $newdoc->appendChild($node);
            $html = $newdoc->saveHTML();

            if( !$expedition )
                print $html;
        }
    }




/////////////////////////////////////////////////////
///
/// FW NAME
///
/////////////////////////////////////////////////////

    $tag_array = array( "aa" => "fw_cluster", "ab" => "fw_single", "ac" => "virtual_fw" );


    foreach( $tag_array as $key1 => $tag )
    {
        $fw_clusters = $doc->getElementsByTagName($tag);

        #print PH::boldText( $tag )."\n";
        foreach ($fw_clusters as $key2 => $fw_cluster)
        {
            $valueID = $fw_cluster->getAttribute('name');
            #$dbKey = $fw_cluster->getAttribute('db_key');
            #print $key1.$key2.": ".$valueID."\n";

            $firewalls[ $key1.$key2 ]['name'] = $valueID;
            #$firewalls[ $key1.$key2 ]['dbkey'] = $dbKey;
        }
    }



/////////////////////////////////////////////////////
///
/// Policy NAME
///
/////////////////////////////////////////////////////

    $tag = "fw_policy";
    $fw_policies = $doc->getElementsByTagName($tag);


    foreach ($fw_policies as $key2 => $fw_policy)
    {
        $valueID = $fw_policy->getAttribute('name');
        #$dbKey = $fw_policy->getAttribute('db_key');
        #print "B".$key2.": ".$valueID."\n";


        $policy[ "b".$key2 ]['name'] = $valueID;
        #$policy[ "b".$key2 ]['dbkey'] = $dbKey;
    }



    if( count($firewalls) > count( $policy ) )
    {
        $array1 = $firewalls;
        $array2 = $policy;

        $kk = count( $firewalls );
    }
    else
    {
        $array2 = $firewalls;
        $array1 = $policy;

        $kk = count( $policy );
    }


    if( !$expedition )
    {
        print "-------------------------------------------\n\n";

        for( $k = 0; $k < $kk; $k++ )
        {
            if( isset( array_values($firewalls)[$k] ) && isset( array_values($policy)[$k] ) )
                print str_pad(str_pad( array_keys($firewalls)[$k].": ", 5, " ", STR_PAD_LEFT).array_values($firewalls)[$k]['name'],40) ." | ".array_keys($policy)[$k].": ".str_pad( array_values($policy)[$k]['name'],32)."\n";
            elseif( isset( array_values($firewalls)[$k] ) )
            {
                print str_pad(str_pad( array_keys($firewalls)[$k].": ", 5, " ", STR_PAD_LEFT).array_values($firewalls)[$k]['name'],40) ." | "."\n";
            }
            elseif( isset( array_values($policy)[$k] ) )
            {
                print str_pad(" ",40) ." | ".array_keys($policy)[$k].": ".str_pad( array_values($policy)[$k]['name'],32)."\n";
            }
        }
    }


}

function stonesoft_mapping( $firewalls, $policy, &$mapping )
{
    print "\n";
    print "-------------------------------------------\n\n";

    print "now it is time to map firewall and policy; please first give as a list of firewalls based on the column 'aX': [example: aa0,aa3]\n";
    print "->";
    $handle = fopen ("php://stdin","r");
    $line = fgets($handle);


    $line = strip_hidden_chars( $line );
    $line = str_replace( " ", "", $line );
    $line = trim( $line );
    print "INPUT found: '".$line."'\n";

    $line_array = explode( ",", $line );
#print_r( $line_array ) ;


    print "-------------------------------------------\n\n";


    $mapping = array();
    foreach( $line_array as $entry )
    {
        print "please tell us the policy for firewall: ".$entry." '".$firewalls[$entry]['name']."'\n";
        print "->";
        $handle = fopen ("php://stdin","r");
        $line = fgets($handle);

        $line = strip_hidden_chars( $line );
        $line = str_replace( " ", "", $line );
        $line = trim( $line );
        print "INPUT found: '".$line."'\n";

        print "map firewall: ".$entry." [ '".$firewalls[$entry]['name']."' ] - with policy: ".$line." [ '".$policy[$line]['name']."' ]\n\n";
        $mapping[ $entry ] = $line;
    }

#print_r($mapping);



}










