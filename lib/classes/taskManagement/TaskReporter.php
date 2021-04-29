<?php


interface TaskReporter
{
    public function start();

    /***
     * Returns true if the task has been cancelled
     */
    public function isCancelled();

    /***
     * Reports this task as started
     * @return mixed
     */
    public function setStarted();

    /***
     * Updates the task status to flag to be relaunched in a given period of time
     *
     * @param STRING $timeUnit
     * @param INT $timeValue
     * @param STRING $submessage
     * @return mixed
     */
    public function setToRelaunch( $timeUnit,  $timeValue,  $submessage);

    /***
     * @param STRING|NULL $submessage
     * @param STRING|NULL $resultCode
     * @return mixed
     */
    public function setCompleted( $submessage = null,  $resultCode = null);

    /***
     * @param STRING|NULL $submessage
     * @param STRING|NULL $resultCode
     * @return mixed
     */
    public function setCompletedSilent( $subMessage = null,  $resultCode = null);

    /***
     * @param STRING|NULL $submessage
     * @param STRING|NULL $resultCode
     * @return mixed
     */
    public function setFailed( $subMessage = null,  $resultCode = null);

    /***
     * @param STRING|NULL $submessage
     * @param STRING|NULL $resultCode
     * @return mixed
     */
    public function setFailedSilent( $subMessage = null,  $resultCode = null);

    public function increaseFailed();

    public function increaseCompleted();

    /***
     * @param STRING|NULL $percentage
     * @param BOOL $correct
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     * @return mixed
     */
    public function updateTaskStatus( $percentage,  $correct,  $subMessage = null,  $resultCode = null);

    /*
    public function notifyCompletedTaskJob();

    public function notifyFailedTaskJob();
*/
}