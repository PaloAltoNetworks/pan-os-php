<?php

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once(dirname(__FILE__)."/UTIL.php");


class logWriter
{
    /**
     * $log_file - path and log file name
     * @var string
     */
    protected $log_file;
    /**
     * $file - file
     * @var string
     */
    protected $file;
    /**
     * $options - settable options - future use - passed through constructor
     * @var array
     */
    protected $options = array(
        'dateFormat' => 'd-M-Y H:i:s'
    );

    /**
     * Class constructor
     * @param string $log_file - path and filename of log
     * @param array $params
     * @throws
     */
    public function __construct($log_file = "", $params = array())
    {
        $log_folder = __DIR__ . "/../../log";
        $log_file = $log_folder."/tool-log.txt";
        $this->log_file = $log_file;
        $this->params = array_merge($this->options, $params);
        //Create log file if it doesn't exist.
        if( !file_exists($log_file) )
        {
            if( !file_exists($log_folder) )
            {
                mkdir($log_folder, 0777, true);
            }
            fopen($log_file, 'w') or exit("Can't create $log_file!");
        }
        //Check permissions of file.
        if( !is_writable($log_file) )
        {
            //throw exception if not writable
            throw new Exception("ERROR: Unable to write to file!", 1);
        }
    }

    /**
     * Info method (write info message)
     * @param string $message
     * @return void
     */
    public function info($message)
    {
        $this->writeLog($message, 'INFO');
    }

    /**
     * Debug method (write debug message)
     * @param string $message
     * @return void
     */
    public function debug($message)
    {
        $this->writeLog($message, 'DEBUG');
    }

    /**
     * Warning method (write warning message)
     * @param string $message
     * @return void
     */
    public function warning($message)
    {
        $this->writeLog($message, 'WARNING');
    }

    /**
     * Error method (write error message)
     * @param string $message
     * @return void
     */
    public function error($message)
    {
        $this->writeLog($message, 'ERROR');
    }

    /**
     * Write to log file
     * @param string $message
     * @param string $severity
     * @return void
     */
    public function writeLog($message, $severity)
    {

        global $expedition;


        // open log file
        if( !is_resource($this->file) )
        {
            $this->openLog();
        }
        // grab the url path ( for troubleshooting )
        #$path = $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
        $path = "EMPTY - define";

        if( $expedition != null )
        {
            $path = "EXPEDITION";

            /*
                MariaDB [(none)]> use pandbRBAC;
                Reading table information for completion of table and column names
                You can turn off this feature to get a quicker startup with -A

                Database changed
                MariaDB [pandbRBAC]> describe tasks;
                +---------------+--------------+------+-----+---------------------+----------------+
                | Field         | Type         | Null | Key | Default             | Extra          |
                +---------------+--------------+------+-----+---------------------+----------------+
                | id            | int(11)      | NO   | PRI | NULL                | auto_increment |
                | job_id        | int(11)      | NO   |     | NULL                |                |
                | taskType      | varchar(45)  | NO   |     | NULL                |                |
                | processCode   | varchar(255) | NO   |     | NULL                |                |
                | params        | text         | NO   |     | NULL                |                |
                | statusCode    | int(11)      | YES  |     | 0                   |                |
                | created_at    | timestamp    | NO   |     | 0000-00-00 00:00:00 |                |
                | updated_at    | timestamp    | NO   |     | 0000-00-00 00:00:00 |                |
                | statusMessage | text         | NO   |     | NULL                |                |
                | taskName      | varchar(255) | NO   |     | Remote Task         |                |
                | resultCode    | varchar(255) | YES  |     | NULL                |                |
                | retry         | int(11)      | YES  |     | NULL                |                |
                | pid           | int(11)      | YES  |     | NULL                |                |
                +---------------+--------------+------+-----+---------------------+----------------+
                13 rows in set (0.01 sec)
             */
        }

        //Grab time - based on timezone in php.ini
        UTIL::setTimezone();
        $time = date($this->params['dateFormat']);
        // Write time, url, & message to end of file
        fwrite($this->file, "[$time] [$path] : [$severity] - $message" . PHP_EOL);
    }

    /**
     * Open log file
     * @return void
     */
    private function openLog()
    {
        $openFile = $this->log_file;
        // 'a' option = place pointer at end of file
        $this->file = fopen($openFile, 'a') or exit("Can't open $openFile!");
    }

    /**
     * Class destructor
     */
    public function __destruct()
    {
        if( $this->file )
        {
            fclose($this->file);
        }
    }

}