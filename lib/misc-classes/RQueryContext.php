<?php

/**
 * Class RQueryContext
 * @ignore
 */
class RQueryContext
{
    public $object;

    public $value;

    public $rQueryObject;

    public $nestedQueries;

    function __construct(RQuery $r, $value = null, $nestedQueries = null)
    {
        $this->rQueryObject = $r;
        $this->value = $value;

        if( $nestedQueries === null )
            $this->nestedQueries = array();
        else
            $this->nestedQueries = &$nestedQueries;
    }

    /**
     * @param $object Tag
     * @return bool
     */
    function execute($object, $nestedQueries = null)
    {
        if( $nestedQueries !== null )
            $this->nestedQueries = &$nestedQueries;

        $this->object = $object;

        if( $this->rQueryObject->argumentList !== null )
            $this->value = &$this->rQueryObject->argumentList;
        else
            $this->value = &$this->rQueryObject->argument;

        return $this->rQueryObject->refOperator['Function']($this);
    }

}