<?php

define('CANCELLED', -1);
define('PENDING', 0);
define('COMPLETED', 1);
define('TO_RELAUNCH', 2);
define('FAILED', 3);

define('STARTED', 10);

class ExpeditionTaskReporter implements TaskReporter
{
    /* @var int $taskId */
    private $taskId;

    /* @var Mysqli $dbConnection */
    private $dbConnection;

    private $dbIP;
    private $dbUser;
    private $dbPass;
    private $db;

    /***
     * @param INT $taskId
     */
    public function __construct( $taskId, $dbIP, $dbUser, $dbPW)
    {
        $this->taskId = $taskId;
        $this->dbIP = $dbIP . ':3306';
        $this->dbUser = $dbUser;//root
        $this->dbPass = $dbPW;//paloalto
        $this->db = 'pandbRBAC';
        $this->establishConnection();
    }

    private function establishConnection()
    {
        $this->dbConnection = new mysqli($this->dbIP, $this->dbUser, $this->dbPass, $this->db);
        $this->dbConnection->ping();

        if( $this->dbConnection->connect_error )
        {
            trigger_error('Database connection failed: ' . $this->dbConnection->connect_error, E_USER_ERROR);
            return FALSE;
        }

        return TRUE;
    }

    /***
     * @param STRING $msg
     */
    public function log( $msg, $level = 1)
    {
        //TODO
        PH::print_stdout( "$msg" );
//        require_once INC_ROOT.'/libs/common/MTLogger.php';
//        $logger = (new MTLogger)->getInstance();
//        $logger->log($msg, $level);
    }

    public function getSender()
    {
        return $this->sender;
    }

    public function start()
    {
        $this->log(date(DATE_RFC2822) . " Start Task", 0);
        $this->setStarted();
    }

    public function end()
    {
        $this->log(date(DATE_RFC2822) . " End Task\n\n", 0);
    }

    public function isCancelled()
    {
        $query = "SELECT * FROM tasks WHERE id=" . $this->taskId . "\n";
        $result = $this->dbConnection->query($query);
        if( $result->num_rows == 0 )
        {
            $data = $result->fetch_assoc();
            if( $data['statusCode'] < 0 )
            {
                return TRUE; //Task has been cancelled
            }
            else
            {
                return FALSE; //Task exists and is not cancelled
            }
        }
        else
        {
            return TRUE; //Task does not exist
        }
    }

    public function setStarted()
    {
        //$this->establishConnection();
        $query = "UPDATE tasks SET statusCode = " . STARTED . ", statusMessage='Started' WHERE id =" . $this->taskId . ";";
        $this->dbConnection->query($query);
        if( !$this->dbConnection->affected_rows == 1 ) return FALSE;

        return TRUE;
    }

    /***
     * @param STRING $metric
     * @param INT $units
     * @param STRING $submessage
     */
    public function setToRelaunch( $metric,  $units,  $submessage)
    {
        switch ($metric)
        {
            case "days":
                $time = $units * 24 * 360;
                break;
            case "hours":
                $time = $units * 360;
                break;
            case "minutes":
                $time = $units * 60;
                break;
            case 'seconds':
            default:
                $time = $units;
                break;

        }

        $query = "UPDATE tasks SET statusCode = " . TO_RELAUNCH . ", statusMessage='To relaunch. $submessage', retry='$time'  WHERE id =" . $this->taskId . ";";
        $this->dbConnection->query($query);

    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setCompleted( $submessage = null,  $resultCode = null)
    {
        $submessage = is_null($submessage) ? '' : $submessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;


        $query = "UPDATE tasks SET statusCode = " . COMPLETED . ", statusMessage = 'Completed. $submessage', resultCode=$resultCode WHERE id =" . $this->taskId . ";";
        $result = $this->dbConnection->query($query);

        if( $result->num_rows == 0 )
        { //Log there was a problem finding the job
            PH::print_stdout( "Job not found" );
            return FALSE;
        }

        $this->notifyCompletedTaskJob();
        return TRUE;
    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setCompletedSilent( $subMessage = null,  $resultCode = null)
    {
        $subMessage = is_null($subMessage) ? '' : $subMessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;


        $query = "UPDATE tasks SET statusCode = " . COMPLETED . ", statusMessage = 'Completed. $subMessage', resultCode=$resultCode WHERE id =" . $this->taskId . ";";
        $this->dbConnection->query($query);
    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setFailed( $subMessage = null,  $resultCode = null)
    {
        $subMessage = is_null($subMessage) ? '' : $subMessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;


        $query = "UPDATE tasks SET statusCode = " . FAILED . ", statusMessage = 'Failed. $subMessage', resultCode=$resultCode WHERE id =" . $this->taskId . ";";
        $result = $this->dbConnection->query($query);
        if( $result->num_rows == 0 )
        { //Log there was a problem finding the job
            PH::print_stdout(  "Job not found");
            return;
        }

        $this->notifyFailedTaskJob();
    }

    /***
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function setFailedSilent( $subMessage = null,  $resultCode = null)
    {
        $subMessage = is_null($subMessage) ? '' : $subMessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;


        $query = "UPDATE tasks SET statusCode = " . FAILED . ", statusMessage = 'Failed. $subMessage', resultCode=$resultCode WHERE id =" . $this->taskId . ";";
        $this->dbConnection->query($query);
    }

    public function increaseFailed()
    {
        $this->notifyFailedTaskJob();
    }

    public function increaseCompleted()
    {
        $this->notifyCompletedTaskJob();
    }

    /***
     * @param STRING $percentage
     * @param BOOL $correct
     * @param STRING|NULL $subMessage
     * @param STRING|NULL $resultCode
     */
    public function updateTaskStatus( $percentage,  $correct,  $subMessage = null,  $resultCode = null)
    {
        $subMessage = is_null($subMessage) ? '' : $subMessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;
        if( $correct )
        {
            if( $percentage == '1.00' )
            {
                $query = "UPDATE tasks SET statusCode=" . COMPLETED . ", statusMessage='Completed. $subMessage', resultCode='$resultCode' WHERE id=" . $this->taskId;
            }
            else
            {
                $query = "UPDATE tasks SET statusMessage='$subMessage', resultCode='$resultCode' WHERE id=" . $this->taskId;
            }
        }
        else
        {
            $query = "UPDATE tasks SET statusCode=" . FAILED . ", statusMessage='Failed. $subMessage', resultCode='$resultCode' WHERE id=" . $this->taskId;
        }


        if( $correct )
        {
            $this->notifyCompletedTaskJob();
        }
        else
        {
            $this->notifyFailedTaskJob();
        }
    }

    public function notifyCompletedTaskJob()
    {

        PH::print_stdout(  "Calling notifyCompletedTaskJob" );
        $query = "SELECT job_id FROM tasks WHERE id=$this->taskId LIMIT 1";

        $result = $this->dbConnection->query($query);
        if( $result->num_rows > 0 )
        {
            $data = $result->fetch_assoc();
            $jobID = $data['job_id'];
            $updateQuery = "UPDATE jobs SET completed=completed+1 WHERE id=$jobID;";
            $this->dbConnection->query($updateQuery);
            if( !$this->dbConnection->affected_rows == 1 ) return FALSE;

            $checkParentJobQuery = "SELECT parentJob FROM jobs WHERE id=$jobID LIMIT 1;";
            $resultParent = $this->dbConnection->query($checkParentJobQuery);
            if( $resultParent->num_rows > 0 )
            {
                $dataParent = $resultParent->fetch_assoc();
                $parentJobID = $dataParent['parentJob'];
                $updateParentQuery = "UPDATE jobs SET completed=completed+1 WHERE id = $parentJobID;";
                $this->dbConnection->query($updateParentQuery);
                if( !$this->dbConnection->affected_rows == 1 ) return FALSE;
            }
            return TRUE;
        }

        return FALSE;
    }


    public function notifyFailedTaskJob()
    {
        $query = "SELECT job_id FROM tasks WHERE id=$this->taskId LIMIT 1";

        $result = $this->dbConnection->query($query);
        if( $result->num_rows > 0 )
        {
            $data = $result->fetch_assoc();
            $jobID = $data['job_id'];
            $updateQuery = "UPDATE jobs SET completed=completed+1, failed=failed+1 WHERE id=$jobID;";
            $this->dbConnection->query($updateQuery);
            if( !$this->dbConnection->affected_rows == 1 ) return FALSE;

            $checkParentJobQuery = "SELECT parentJob FROM jobs WHERE id=$jobID LIMIT 1;";
            $resultParent = $this->dbConnection->query($checkParentJobQuery);
            if( $resultParent->num_rows > 0 )
            {
                $dataParent = $resultParent->fetch_assoc();
                $parentJobID = $dataParent['parentJob'];
                $updateParentQuery = "UPDATE jobs SET completed=completed+1, failed=failed+1 WHERE id = $parentJobID;";
                $this->dbConnection->query($updateParentQuery);
                if( !$this->dbConnection->affected_rows == 1 ) return FALSE;
            }
            return TRUE;
        }

        return FALSE;
    }
}