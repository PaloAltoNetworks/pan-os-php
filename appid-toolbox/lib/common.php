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


require_once("lib/pan_php_framework.php");

$minimumVersion = "1.5.13";
$maximumVersion = "2.1.0";

// Check version of PAN-PHP-framework for compatibility
if( ! PH::frameworkVersion_isGreaterThan($minimumVersion) || PH::frameworkVersion_isGreaterThan($maximumVersion) )
    derr("AppID Toolbox requires PAN-PHP-framework version  > {$minimumVersion} and  < $maximumVersion while current version is ".PH::frameworkVersion()."\n");

if( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' )
{
    $system_timezone = exec('tzutil /g');

    $temp = explode(' ', $system_timezone);
    $result = '';
    foreach($temp as $t)
        $result .= $t[0];

    $system_timezone = strtoupper($result);
}
else
{
    $system_timezone = exec('date +%Z');
}

$timezone_name = timezone_name_from_abbr( $system_timezone );
if( !$timezone_name  )
    $timezone_name = "GMT";
date_default_timezone_set( $timezone_name );


#date_default_timezone_set("GMT");
print " - TIMEZONE is set to: ".date_default_timezone_get()."\n";

class DeviceGroupRuleAppUsage
{
    public $logs = Array();

    public function load_from_file($filename)
    {
        $xmlDoc = new DOMDocument();
        $xmlDoc->Load($filename);

        $recordsNode = DH::findFirstElementOrDie('records', $xmlDoc);

        foreach( $recordsNode->childNodes as $entryNode )
        {
            if( $entryNode->nodeType != XML_ELEMENT_NODE )
                continue;

            $logRecord = Array( 'apps' => Array() );

            /** @var DOMElement $entryNode */

            $ruleName = $entryNode->getAttribute('name');

            if( ! $entryNode->hasAttribute('timestamp') )
                $logRecord['timestamp'] = time();
            else
                $logRecord['timestamp'] = $entryNode->getAttribute('timestamp');

            foreach( $entryNode->childNodes as $appNode )
            {
                if( $appNode->nodeType != XML_ELEMENT_NODE )
                    continue;

                /** @var DOMElement $appNode */

                $logRecord['apps'][$appNode->getAttribute('name')] = Array( 'name' => $appNode->getAttribute('name'), 'count' => $appNode->getAttribute('count'));
            }

            $this->logs[$ruleName] = &$logRecord;
            unset($logRecord);
        }


    }

    public function save_to_file($filename)
    {
        $xml = "<records>\n";

        foreach($this->logs as $name => &$log)
        {
            $xml .= "  <entry name=\"{$name}\" timestamp=\"{$log['timestamp']}\" Htimestamp=\"".timestamp_to_date($log['timestamp'])."\">\n";

            foreach( $log['apps'] as &$app )
            {
                $xml .= "    <app name=\"{$app['name']}\" count=\"{$app['count']}\"/>\n";
            }

            $xml .= "  </entry>\n";
        }

        $xml .= '</records>';

        file_put_contents($filename, $xml);
    }

    public function addRuleStats($ruleName , $appName, $hitCount)
    {
        if( isset($this->logs[$ruleName]) )
        {
            $record = &$this->logs[$ruleName];
        }
        else
        {
            $record = Array( 'apps' => Array() );
            $this->logs[$ruleName] = &$record;
        }

        $record['timestamp'] = time();

        if( isset($record['apps'][$appName]) )
            $record['apps'][$appName]['count'] += $hitCount;
        else
            $record['apps'][$appName] = Array('name'=>$appName, 'count' => $hitCount);
    }

    /**
     * @param string $ruleName
     * @return null|int
     */
    public function getRuleUpdateTimestamp($ruleName)
    {
        if( isset($this->logs[$ruleName]) )
        {
            return $this->logs[$ruleName]['timestamp'];
        }
        return null;
    }


    public function resetRulesStats($ruleName)
    {
        if( isset($this->logs[$ruleName]) )
            unset($this->logs[$ruleName]);
    }


    public function getRuleStats($ruleName)
    {
        if( !isset($this->logs[$ruleName]) )
            return null;

        return $this->logs[$ruleName]['apps'];
    }

    public function isRuleUsed($ruleName, $ignoreApps = Array('incomplete', 'non-syn-tcp') )
    {
        if( !isset($this->logs[$ruleName]) )
            return null;

        $apps = & $this->logs[$ruleName]['apps'];

        foreach($apps as $app )
            if(  ! array_search($app['name'], $ignoreApps) )
                return true;

        return false;

    }

    public function createRuleStats($ruleName)
    {
        if( !isset($this->logs[$ruleName]) )
        {
            $record = Array( 'apps' => Array(), 'timestamp' => time() );
            $this->logs[$ruleName] = &$record;
        }
    }

    public function updateRuleUpdateTimestamp($ruleName)
    {
        if( isset($this->logs[$ruleName]) )
        {
            $this->logs[$ruleName]['timestamp'] = time();
        }
    }

    public function exportToCSV($filename)
    {
        $content = file_get_contents(dirname(__FILE__).'/html/export-template.html');

        $content = str_replace('%TableHeaders%',
            '<th>app-name</th><th>count</th>',
            $content);

        //$content = str_replace('%lines%', $lines, $content);

        $jscontent =  file_get_contents(dirname(__FILE__).'/html/jquery-1.11.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__).'/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        /*
         * TODO: finalize CSV export - get data
         * //copied from XML export
         foreach($this->logs as $name => &$log)
        {
            $xml .= "  <entry name=\"{$name}\" timestamp=\"{$log['timestamp']}\" Htimestamp=\"".timestamp_to_date($log['timestamp'])."\">\n";

            foreach( $log['apps'] as &$app )
            {
                $xml .= "    <app name=\"{$app['name']}\" count=\"{$app['count']}\"/>\n";
            }

            $xml .= "  </entry>\n";
        }
         */

        file_put_contents($filename, $content);

    }

}


class RuleIDTagLibrary
{
    public $_tagsToObjects = Array();
    public $_objectsToTags = Array();

    static public $tagBaseName = 'appRID#';

    /**
     * @param SecurityRule[] $ruleArray
     */
    public function readFromRuleArray(&$ruleArray)
    {
        foreach( $ruleArray as $rule )
        {
            $words = $rule->description();
            $words = str_replace("\n", ' ', $words);
            $words = str_replace("\r", ' ', $words);
            $words = explode(' ', $words );

            foreach( $words as &$word )
            {
                $word = trim($word);

                if( strpos($word, self::$tagBaseName) === 0 )
                {
                    $this->addRuleToTag($rule, $word);
                    break;
                }
            }
        }
    }

    /**
     * @param $rule SecurityRule
     * @param $tagName string
     */
    public function addRuleToTag( $rule, $tagName)
    {
        $serial = spl_object_hash($rule);

        if( !isset($this->_tagsToObjects[$tagName]) )
            $this->_tagsToObjects[$tagName] = Array();
        $this->_tagsToObjects[$tagName][$serial] = $rule;

        if( !isset($this->_objectsToTags[$serial]) )
            $this->_objectsToTags[$serial] = Array();
        $this->_objectsToTags[$serial][$tagName] = $tagName;
    }

    public function isTagAvailable( $tagName )
    {
        if( !isset($this->_tagsToObjects[$tagName]) )
            return true;

        if( count($this->_tagsToObjects[$tagName]) == 0 )
        {
            unset($this->_tagsToObjects[$tagName]);
            return true;
        }

        return false;
    }

    /**
     * @param $baseName string
     * @return string
     */
    public function findAvailableTagName( $baseName )
    {
        $inc = 1;

        while( true )
        {
            $name = $baseName.$inc;

            if( !isset($this->_tagsToObjects[$name]) )
            {
                return $name;
            }

            $inc++;
        }
    }

    /**
     * @param $rule SecurityRule
     * @return bool
     */
    public function ruleIsTagged($rule)
    {
        $serial = spl_object_hash($rule);

        if( isset($this->_objectsToTags[$serial]) && count($this->_objectsToTags[$serial]) > 0 )
            return true;

        return false;
    }

    public function tagCount()
    {
        return count($this->_tagsToObjects);
    }

    static public function cleanRuleDescription(SecurityRule $rule, $offline = true)
    {
        $desc = preg_replace('/appRID#[0-9]+/', '', $rule->description());
        if( $offline )
            $rule->setDescription($desc);
        else
            $rule->API_setDescription($desc);
    }

}

class TH
{
    static public $tagBase = 'appid#';

    static public $tagNtbrBase = 'NTBR#';

    static public $tagActivatedBase = 'activated#';

    static public $tag_NTBR_tooManyApps = 'tooManyApps';
    /** @var Tag */
    static public $tag_NTBR_tooManyApps_tagObject = null;

    static public $tag_NTBR_hasUnknownApps = 'hasUnknownApps';
    /** @var Tag */
    static public $tag_NTBR_hasUnknownApps_tagObject = null;

    static public $tag_NTBR_onlyInvalidApps = 'onlyInvalidApps';
    /** @var Tag */
    static public $tag_NTBR_onlyInvalidApps_tagObject = null;

    static public $tag_NTBR_hasInsufficientData = 'hasInsufficientData';
    /** @var Tag */
    static public $tag_NTBR_hasInsufficientData_tagObject = null;

    static public $tag_NTBR_appNotAny = 'appNotAny';
    /** @var Tag */
    static public $tag_NTBR_appNotAny_tagObject = null;


    static public $tag_misc_ignore = 'ignore';
    /** @var Tag */
    static public $tag_misc_ignore_tagObject = null;


    static public $tag_misc_clonedRule = 'clonedRule';
    /** @var Tag */
    static public $tag_misc_clonedRule_tagObject = null;


    static public $tag_misc_convertedRule = 'converted';
    /** @var Tag */
    static public $tag_misc_convertedRule_tagObject = null;

    static public $tag_misc_unused = 'unused';
    /** @var Tag */
    static public $tag_misc_unused_tagObject = null;




    static public function init()
    {
        self::$tagNtbrBase = self::$tagBase . self::$tagNtbrBase;
        self::$tagActivatedBase = self::$tagBase . self::$tagActivatedBase;

        $reflection = new ReflectionClass('TH');
        $properties =  $reflection->getProperties(ReflectionMethod::IS_STATIC);

        foreach( $properties as $var )
        {
            $varName = $var->name;
            if( strpos($varName, 'tag_NTBR_') === 0 )
            {
                if( strpos($varName, '_tagObject') === false )
                    self::$$varName = self::$tagNtbrBase . self::$$varName;
            }
            elseif( strpos($varName, 'tag_misc_') === 0 )
            {
                if( strpos($varName, '_tagObject') === false )
                    self::$$varName = self::$tagBase . self::$$varName;
            }
        }

    }

    /**
     * @param $pan PANConf|PanoramaConf
     */
    static public function createTags($pan, $configInputType)
    {
        $reflection = new ReflectionClass('TH');
        $properties =  $reflection->getProperties(ReflectionMethod::IS_STATIC);

        if( $pan->isPanorama() )
            $store = $pan->tagStore;
        else
        {
            if( count($pan->virtualSystems) > 1 )
                $store = $pan->tagStore;
            else
                $store = $pan->findVirtualSystem('vsys1')->tagStore;

        }

        foreach( $properties as $var )
        {
            $varName = $var->name;
            if( strpos($varName, 'tag_NTBR_') === 0 || strpos($varName, 'tag_misc_') === 0 )
            {
                if( strpos($varName, '_tagObject') === false )
                {
                    $tagVarName = $varName.'_tagObject';

                    self::$$tagVarName = $store->find(self::$$varName);
                    if( self::$$tagVarName === null )
                        if( $configInputType == 'api' )
                            self::$$tagVarName = $store->API_createTag(self::$$varName);
                        else
                            self::$$tagVarName = $store->createTag(self::$$varName);
                }

            }
        }

    }

    static public function cleanActivatedTag(SecurityRule $rule, $offline = true)
    {
        foreach( $rule->tags->tags() as $tag )
        {
            if( strpos($tag->name(), TH::$tagActivatedBase) === 0 )
            {
                if ($offline)
                    $rule->tags->removeTag($tag);
                else
                    $rule->tags->API_removeTag($tag);
            }
        }
    }

    static public function cleanClonedTag(SecurityRule $rule, $offline = true)
    {
        foreach( $rule->tags->tags() as $tag )
        {
            if( $tag->name() == TH::$tag_misc_clonedRule )
            {
                if( $offline )
                    $rule->tags->removeTag($tag);
                else
                    $rule->tags->API_removeTag($tag);
            }
        }
    }
}
TH::init();

function days_between_timestamps($t1, $t2)
{
    $days = ($t1 - $t2) / (24 * 60 * 60);
    return $days;
}

function timestamp_to_date($t1)
{
    return date("j-M-Y G:i", $t1);
}




