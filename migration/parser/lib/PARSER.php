<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 3/6/16 - 13:14
 */

//namespace PaloAltoNetworks\Processes;


abstract class PARSER extends CONVERTER
{

    /** @var bool */
    protected $loggable;

    /** @var string */
    protected $logPath;

    /** @var mixed|null */
    protected $sender;

    protected $params;

    protected $taskId;
    protected $param2;
    protected $param3;
    protected $comesFromExpedition;

    protected $logger;


    public function __construct( $taskId = 0, $expedition = FALSE, $expedition_ip = 'localhost', $expedition_user = 'root', $expedition_pw = 'paloalto')
    {
        $this->taskId = $taskId;
        $this->comesFromExpedition = $expedition;
        if( $expedition )
        {
            $this->logger = new ExpeditionTaskReporter($taskId, $expedition_ip, $expedition_user, $expedition_pw);
        }
        else
        {
            $this->logger = new FileTaskReporter();
        }
    }

    public function log(String $msg, $level = 1)
    {
        require_once INC_ROOT . '/libs/common/MTLogger.php';
        $logger = (new MTLogger)->getInstance();
        $logger->log($msg, $level);
    }

    public function getSender()
    {
        return $this->sender;
    }

    public abstract function vendor_main();

    public function start()
    {
        $this->log(date(DATE_RFC2822) . " Start Task", 0);
        $this->vendor_main();
        $this->log(date(DATE_RFC2822) . " End Task\n\n", 0);
    }

    public function preCheck()
    {
        if( $this->logger->isCancelled() )
        {
            return FALSE;
        }
        return TRUE;
    }

    function isCancelled()
    {
        global $app;

        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return TRUE;
        }

        if( $task->statusCode < 0 )
        {
            return TRUE;
        }
        return FALSE;
    }

    function setStarted()
    {
        global $app;
        $taskParams = [
            'statusCode' => STARTED,
        ];

        /**
         * @var $task \PaloAltoNetworks\MTJobs\Tasks\Task
         */
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);
    }

    function setToRelaunch(STRING $metric, INT $units, STRING $submessage)
    {
        global $app;
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

        $taskParams = [
            'statusCode' => TO_RELAUNCH,
            'statusMessage' => 'Completed. ' . $submessage,
            'retry' => $time,
        ];

        //TODO: Implement the updated time for the new launching moment
        return $taskParams;

    }

    function setCompleted(STRING $submessage = null, STRING $resultCode = null)
    {

        global $app;
        $submessage = is_null($submessage) ? '' : $submessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;

        $taskParams = [
            'statusCode' => COMPLETED,
            'statusMessage' => 'Completed. ' . $submessage,
            'resultCode' => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }

        $this->notifyCompletedTaskJob($job);
    }

    function increaseFailed()
    {
        global $app;
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
        $this->notifyFailedTaskJob($job);
    }

    function increaseCompleted()
    {
        global $app;
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
        $this->notifyCompletedTaskJob($job);
    }

    function updateTaskStatus(STRING $submessage = null, STRING $resultCode = null, STRING $percentage, BOOL $correct)
    {
        global $app;
        $submessage = is_null($submessage) ? '' : $submessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;
        if( $correct )
        {
            if( $percentage == '1.00' )
            {
                $taskParams = [
                    'statusCode' => COMPLETED,
                    'statusMessage' => 'Completed. ' . $submessage,
                    'resultCode' => $resultCode,
                ];
            }
            else
            {
                $taskParams = [
                    'statusMessage' => $submessage,
                    'resultCode' => $resultCode,
                ];
            }
        }
        else
        {
            $taskParams = [
                'statusCode' => FAILED,
                'statusMessage' => 'Failed. ' . $submessage,
                'resultCode' => $resultCode,
            ];
        }

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
        else
        {
            if( $correct )
            {
                $jobParams = [
                    'completed' => $percentage,
                ];
            }
            else
            {
                $jobParams = [
                    'completed' => $percentage,
                    'failed' => $percentage
                ];
            }
            $job->update($jobParams);

        }
    }

    function setCompletedSilent(STRING $submessage = null, STRING $resultCode = null)
    {
        global $app;
        $submessage = is_null($submessage) ? '' : $submessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;

        $taskParams = [
            'statusCode' => COMPLETED,
            'statusMessage' => 'Completed. ' . $submessage,
            'resultCode' => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
    }

    function setFailed(STRING $submessage = null, STRING $resultCode = null)
    {
        global $app;
        $submessage = is_null($submessage) ? '' : $submessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;
        $taskParams = [
            'statusCode' => FAILED,
            'statusMessage' => 'Completed. ' . $submessage,
            'resultCode' => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }

        $this->notifyFailedTaskJob($job);
    }

    function setFailedSilent(STRING $submessage = null, STRING $resultCode = null)
    {
        global $app;
        $submessage = is_null($submessage) ? '' : $submessage;
        $resultCode = is_null($resultCode) ? '' : $resultCode;

        $taskParams = [
            'statusCode' => FAILED,
            'statusMessage' => 'Completed. ' . $submessage,
            'resultCode' => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if( !($task = $app->task->where('id', $this->params['taskId'])->first()) )
        {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if( !$job = $task->job )
        {
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
    }

    function notifyCompletedTaskJob($job)
    {
        global $app;
        /** @var $job \PaloAltoNetworks\MTJobs\Jobs\Job */
        /** @var $parentJob \PaloAltoNetworks\MTJobs\Jobs\Job */

        $jobParams = [
            'completed' => $job->completed + 1,
        ];
        $job->update($jobParams);

        if( $job->parentJob != '' )
        {
            $parentJob = $app->job->where('id', $job->parentJob)->get()->first();
            $parentJobParams = [
                'completed' => $parentJob->completed + 1,
            ];
            $parentJob->update($parentJobParams);
        }
    }

    function notifyFailedTaskJob($job)
    {
        global $app;
        /** @var $job \PaloAltoNetworks\MTJobs\Jobs\Job */
        /** @var $parentJob \PaloAltoNetworks\MTJobs\Jobs\Job */

        $jobParams = [
            'completed' => $job->completed + 1,
            'failed' => $job->failed + 1,
        ];
        $job->update($jobParams);

        if( $job->parentJob != '' )
        {
            $parentJob = $app->job->where('id', $job->parentJob)->get()->first();
            $parentJobParams = [
                'completed' => $parentJob->completed + 1,
                'failed' => $parentJob->failed + 1,
            ];
            $parentJob->update($parentJobParams);
        }
    }
}