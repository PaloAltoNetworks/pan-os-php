<?php


class FileTaskReporter implements TaskReporter
{

    public function start()
    {
        // TODO: Implement start() method.
        PH::print_stdout(  "The conversion start" );
    }

    /**
     * @inheritDoc
     */
    public function isCancelled()
    {
        // TODO: Implement isCancelled() method.
        #PH::print_stdout(  "The conversion is cancelled");
        return FALSE;
    }

    /**
     * @inheritDoc
     */
    public function setStarted()
    {
        // TODO: Implement setStarted() method.
        $this->start();
    }

    /***
     * @param STRING $timeUnit
     * @param INT $timeValue
     * @param STRING $submessage
     */
    public function setToRelaunch( $timeUnit,  $timeValue,  $submessage)
    {
        // TODO: Implement setToRelaunch() method.
        PH::print_stdout(  "Oj, oj. We will have to rerun this execution. Didn't work now" );
    }

    /***
     * @param STRING|NULL $submessage
     * @param STRING|NULL $resultCode
     */
    public function setCompleted( $submessage = null,  $resultCode = null)
    {
        // TODO: Implement setCompleted() method.
        PH::print_stdout(  "We are DONE" );
    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setCompletedSilent( $subMessage = null,  $resultCode = null)
    {
        // TODO: Implement setCompletedSilent() method.
        $this->setCompleted();
    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setFailed( $subMessage = null,  $resultCode = null)
    {
        // TODO: Implement setFailed() method.
        PH::print_stdout(  "FAILED" );
    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setFailedSilent( $subMessage = null,  $resultCode = null)
    {
        // TODO: Implement setFailedSilent() method.
        $this->setFailed();
    }

    public function increaseFailed()
    {
        // TODO: Implement increaseFailed() method.
        PH::print_stdout(  "This part failed" );
    }

    public function increaseCompleted()
    {
        // TODO: Implement increaseCompleted() method.
        PH::print_stdout(  "This part completed" );
    }

    /***
     * @param STRING $percentage
     * @param BOOL $correct
     * @param STRING|NULL $subMessage
     * * @param STRING|NULL $resultCode
     */
    public function updateTaskStatus( $percentage,  $correct,  $subMessage = null,  $resultCode = null)
    {
        // TODO: Implement updateTaskStatus() method.
    }

    /***
     * @return mixed
     */
    /*
    public function notifyCompletedTaskJob()
    {
        // TODO: Implement notifyCompletedTaskJob() method.
    }

     /***
     * @return mixed
     */
    /*
    public function notifyFailedTaskJob()
    {
        // TODO: Implement notifyFailedTaskJob() method.
    }
    */
}