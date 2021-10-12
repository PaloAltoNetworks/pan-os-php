<?php


class OVERRIDEFINDER extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "php " . basename(__FILE__) . " [delete=hostOrIP] [add=hostOrIP] [test=hostOrIP] [hiddenPW]";

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();

        $this->arg_validation();


        $this->mainKEY();


        $this->endOfScript();
    }

    public function mainKEY()
    {

        if( isset(PH::$args['help']) )
        {
            $this->display_usage_and_exit();
        }


        if( !isset(PH::$args['in']) )
            $this->display_error_usage_exit('"in" is missing from arguments');
        $configInput = PH::$args['in'];
        if( !is_string($configInput) || strlen($configInput) < 1 )
            $this->display_error_usage_exit('"in" argument is not a valid string');

        if( isset(PH::$args['debugapi']) )
            $debugAPI = TRUE;
        else
            $debugAPI = FALSE;

        if( isset(PH::$args['cycleconnectedfirewalls']) )
            $cycleConnectedFirewalls = TRUE;
        else
            $cycleConnectedFirewalls = FALSE;

//
// What kind of config input do we have.
//     File or API ?
//
        $configInput = PH::processIOMethod($configInput, TRUE);

        if( $configInput['status'] == 'fail' )
        {
            fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
            exit(1);
        }

        if( $configInput['type'] == 'file' )
        {
            derr("Only API mode is supported, please provide an API input");
        }
        elseif( $configInput['type'] == 'api' )
        {
            /** @var PanAPIConnector $inputConnector */
            $inputConnector = $configInput['connector'];

            if( $debugAPI )
                $inputConnector->setShowApiCalls(TRUE);
        }
        else
            derr('not supported yet');





        if( $cycleConnectedFirewalls )
        {
            $firewallSerials = $inputConnector->panorama_getConnectedFirewallsSerials();

            $countFW = 0;
            foreach( $firewallSerials as $fw )
            {
                $countFW++;
                PH::print_stdout( " ** Handling FW #{$countFW}/" . count($firewallSerials) . " : serial/{$fw['serial']}   hostname/{$fw['hostname']} **" );
                $tmpConnector = $inputConnector->cloneForPanoramaManagedDevice($fw['serial']);
                $this->checkFirewallOverride($tmpConnector, '    ');
            }
        }
        else
        {
            $this->checkFirewallOverride($inputConnector, ' ');
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['cycleconnectedfirewalls'] = array('niceName' => 'cycleConnectedFirewalls', 'shortHelp' => 'a listing of all devices connected to Panorama will be collected through API then each firewall will be queried for overrides');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
    }


    function diffNodes(DOMElement $template, DOMElement $candidate, $padding)
    {
        static $excludeXpathList = array('/config/devices/entry/deviceconfig/system/update-schedule/*/recurring'

        );

        if( $candidate->hasAttribute('src') && $candidate->getAttribute('src') == 'tpl' )
        {
            foreach( $template->childNodes as $templateNode )
            {
                if( $templateNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                /** @var DOMElement $templateNode */

                if( $templateNode->hasAttribute('name') )
                    $candidateNode = DH::findFirstElementByNameAttrOrDie($templateNode->tagName, $templateNode->getAttribute('name'), $candidate);
                else
                    $candidateNode = DH::findFirstElement($templateNode->tagName, $candidate);

                if( $candidateNode === FALSE )
                {
                    $exclusionFound = FALSE;
                    foreach( $excludeXpathList as $excludeXPath )
                    {
                        $xpathResults = DH::findXPath('/config/template' . $excludeXPath, $template->ownerDocument);

                        foreach( $xpathResults as $searchNode )
                        {
                            /** @var DOMNode $searchNode */
                            if( $searchNode->isSameNode($template) )
                            {
                                $exclusionFound = TRUE;
                                break;
                            }
                        }
                        if( $exclusionFound )
                            break;
                    }


                    if( $exclusionFound )
                    {
                        PH::print_stdout( $padding . "* " . DH::elementToPanXPath($candidate) );
                    }
                    else
                        PH::print_stdout( $padding . "* " . DH::elementToPanXPath($templateNode) . " (defined in template but missing in Firewall config)" );
                }
                else
                    $this->diffNodes($templateNode, $candidateNode, $padding);
            }
        }
        else
        {
            static $manualCheckXpathList = array('/config/mgt-config/users/entry/phash',
                '/config/shared/local-user-database/user/entry/phash',
                '/config/shared/certificate/entry/private-key'

            );

            $exclusionFound = FALSE;
            foreach( $manualCheckXpathList as $excludeXPath )
            {
                $xpathResults = DH::findXPath('/config/template' . $excludeXPath, $template->ownerDocument);
                #$xpathResults = DH::findXPath( $excludeXPath, $template);

                foreach( $xpathResults as $searchNode )
                {
                    /** @var DOMNode $searchNode */
                    if( $searchNode->isSameNode($template) )
                    {
                        $exclusionFound = TRUE;
                        break;
                    }
                }
                if( $exclusionFound )
                    break;
            }

            if( $exclusionFound )
            {
                if( $template->nodeValue != $candidate->nodeValue )
                    $exclusionFound = FALSE;
            }

            if( $exclusionFound )
                return;

            if( $template->nodeValue == $candidate->nodeValue )
                $identicalText = '  (but same value as template)';
            else
                $identicalText = '';

            PH::print_stdout( $padding . "* " . DH::elementToPanXPath($candidate) . "{$identicalText}" );
        }
    }

    /**
     * @param PanAPIConnector $apiConnector
     * @param string $padding
     */
    function checkFirewallOverride($apiConnector, $padding)
    {
        PH::enableExceptionSupport();
        $text = $padding . " - Downloading candidate config...";
        $request = 'type=config&action=get&xpath=/config';

        try
        {
            $candidateDoc = $apiConnector->sendSimpleRequest($request);


            PH::print_stdout( $text );

            $text = $padding . " - Looking for root /config xpath...";
            $configRoot = DH::findXPathSingleEntryOrDie('/response/result/config', $candidateDoc);

            PH::print_stdout( $text );

            DH::makeElementAsRoot($configRoot, $candidateDoc);

            $text = $padding . " - Looking for root /config/template/config xpath...";
            $templateRoot = DH::findXPathSingleEntry('template/config', $configRoot);


            PH::print_stdout( $text );

            if( $templateRoot === FALSE )
            {
                PH::print_stdout( $padding . " - SKIPPED because no template applied!" );
            }
            else
            {
                PH::print_stdout( "" );

                PH::print_stdout( $padding . " ** Looking for overrides **" );

                $this->diffNodes( $templateRoot, $configRoot, $padding);
            }
        } catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( $padding . " ***** an error occured : " . $e->getMessage() );
            return;
        }

        PH::disableExceptionSupport();
    }

    function display_usage_and_exit($shortMessage = FALSE)
    {
        PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=file.xml|api://... [more arguments]" );
        PH::print_stdout( "php " . basename(__FILE__) . " help          : more help messages" );
        PH::print_stdout( PH::boldText("Examples:") );
        PH::print_stdout( " - php " . basename(__FILE__) . " in=api://192.169.50.10 cycleConnectedFirewalls'" );
        PH::print_stdout( " - php " . basename(__FILE__) . " in=api://001C55663D@panorama-host" );

        if( !$shortMessage )
        {
            PH::print_stdout( PH::boldText("\nListing available arguments") );

            ksort($this->supportedArguments);
            foreach( $this->supportedArguments as &$arg )
            {
                $text = " - " . PH::boldText($arg['niceName']);
                if( isset($arg['argDesc']) )
                    $text .= '=' . $arg['argDesc'];
                //."=";
                if( isset($arg['shortHelp']) )
                {
                    PH::print_stdout( $text );
                    $text = "     " . $arg['shortHelp'];
                }
                PH::print_stdout( $text );
            }

            PH::print_stdout("" );
        }

        PH::print_stdout("" );
        exit(1);
    }

    function display_error_usage_exit($msg)
    {
        if( PH::$shadow_json )
            PH::$JSON_OUT['error'] = $msg;
        else
            fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
        $this->display_usage_and_exit(FALSE);
    }
}