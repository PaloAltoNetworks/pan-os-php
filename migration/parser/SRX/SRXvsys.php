<?php


trait SRXvsys
{
    /**
     * @param PANConf|PanoramaConf $pan
     * @return VirtualSystem
     */
    function create_vsys( $lsysName = null )
    {
        /** @var PANConf|PanoramaConf $pan */

        $vsysName = "SRX";
        $vsysID = 1;

        $this->template_vsys = $this->template->findVSYS_by_displayName($vsysName);
        if( $this->template_vsys === null )
        {
            #print "VSYS: ".$vsysID." already available - check displayName ".$vsysName."\n";
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
                if( $lsysName !== null )
                    $this->template_vsys->setAlternativeName($lsysName);

                if( $this->template_vsys === null )
                {
                    derr("vsys" . $vsysID . " could not be created ? Exit\n");
                }
                print "create VSYS: ".$this->template_vsys->name()." - ".$this->template_vsys->alternativeName()."\n";
            }
        }

        if( $this->configType == "panos" )
        {
            $this->sub = $this->template_vsys;
        }
        else
        {
            if( $this->objectsLocationCounter == 0 )
            {
                $this->sub = $this->pan->findDeviceGroup( $this->objectsLocation );
                $this->objectsLocationCounter++;
            }
            else
            {
                $this->sub = $this->pan->createDeviceGroup(  $this->objectsLocation.$this->objectsLocationCounter );
                $this->objectsLocationCounter++;
            }
        }
    }
}