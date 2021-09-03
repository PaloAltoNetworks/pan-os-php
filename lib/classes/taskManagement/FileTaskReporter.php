<?php


class FileTaskReporter implements TaskReporter
{

    public function start()
    {
        // TODO: Implement start() method.
        print "The conversion start\n";
    }

    /**
     * @inheritDoc
     */
    public function isCancelled()
    {
        // TODO: Implement isCancelled() method.
        #print "The conversion is cancelled\n";
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
        print "Oj, oj. We will have to rerun this execution. Didn't work now\n";
    }

    /***
     * @param STRING|NULL $submessage
     * @param STRING|NULL $resultCode
     */
    public function setCompleted( $submessage = null,  $resultCode = null)
    {
        // TODO: Implement setCompleted() method.
        print "We are DONE\n";
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
        print "FAILED\n";
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
        print "This part failed\n";
    }

    public function increaseCompleted()
    {
        // TODO: Implement increaseCompleted() method.
        print "This part completed\n";
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