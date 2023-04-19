<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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

trait CISCOtimerange
{

    public function get_time_range()
    {
        global $print;

        $isTimeRange = 0;

        $tmp_schedule = null;
        $scheduleEntryabsoluteFound = false;
        $scheduleEntryperiodicFound = false;
        foreach( $this->data as $line => $names_line )
        {
            $names_line = trim($names_line);

            if( $names_line == "!" || preg_match("/^banner motd/i", $names_line) )
            {
                $isTimeRange = 0;
            }

            if( $isTimeRange == 1 )
            {
                //absolute [start time date] [end time date]
                //periodic days-of-the-week time to [days-of-the-week] time


                //what todo if schedule object is not empty????

                //$tmp_schedule
                /*
                  absolute end 12:00 1 September 2025
                    periodic weekdays 08:00 to 17:00

                 */
                $array = explode( " ", $names_line );



                if( $array[0] == "absolute" && $scheduleEntryperiodicFound == false )
                {
                    $scheduleEntryabsoluteFound = true;

                    $year = $array[5];

                    $month = $array[4];
                    $month =  date('m', strtotime($month));

                    $day = $array[3];
                    $hour = $array[2];
                    $start = $year."/".$month."/".$day."@".$hour;

                    if( $array[1] == "end" )
                    {
                        $end = $start;
                        $start = "1970/01/01@00:00";

                        if( $print )
                            print "  - set: '".$start."-".$end."'\n";
                        $tmp_schedule->setNonRecurring( $start."-".$end );

                    }
                    elseif( $array[1] == "start" )
                    {
                        if( isset( $array[6] ) && $array[6] == "end" )
                        {
                            $year = $array[10];
                            $month = $array[9];
                            $month =  date('m', strtotime($month));

                            $day = $array[8];
                            $hour = $array[7];
                            $end = $year."/".$month."/".$day."@".$hour;
                        }
                        else
                            $end = "2999/12/31@23:59";

                        if( $print )
                            print "  - set: '".$start."-".$end."'\n";
                        $tmp_schedule->setNonRecurring( $start."-".$end );

                    }

                }
                elseif( $array[0] == "periodic" && $scheduleEntryabsoluteFound == false )
                {
                    $scheduleEntryperiodicFound = true;
                    $scheduleWeekly = array();

                    $print = false;

                    $dayArray = array("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday");
                    $toFound = false;
                    foreach( $array as $entry )
                    {
                        if( $entry == "periodic" )
                            continue;


                        if( $entry == "to" )
                            $toFound = TRUE;
                        elseif( $toFound )
                        {
                            if( in_array($entry, $dayArray) )
                            {
                                //Todo - special treatment as calculation from day to day and hours calculation must be done
                                $addlog = "time-range field not supported for migration " . $names_line;
                                $tmp_schedule->set_node_attribute('warning', $addlog);

                                $days = array();
                                for ($i = 0; $i < 7; $i++) {
                                    $days[$i] = jddayofweek($i,1);
                                }
                                #print_r( $days );
                                #$scheduleWeekly[$entry] = $entry;
                            }
                            else
                            {
                                $scheduleWeekly['to'] = $entry;
                            }
                        }
                        elseif( in_array($entry, $dayArray) )
                        {
                            $scheduleWeekly[$entry] = $entry;
                        }
                        elseif( $entry == "weekend" )
                        {
                            $scheduleWeekly["Saturday"] = "Saturday";
                            $scheduleWeekly["Sunday"] = "Sunday";
                        }
                        elseif( $entry == "weekdays" )
                        {
                            $scheduleWeekly["Monday"] = "Monday";
                            $scheduleWeekly["Tuesday"] = "Tuesday";
                            $scheduleWeekly["Wednesday"] = "Wednesday";
                            $scheduleWeekly["Thursday"] = "Thursday";
                            $scheduleWeekly["Friday"] = "Friday";
                        }
                        elseif( $entry == "daily" )
                        {
                            $scheduleWeekly["daily"] = "daily";
                        }
                        else
                        {
                            $scheduleWeekly['from'] = $entry;
                        }


                    }

                    foreach( $scheduleWeekly as $key => $scheduleEntry )
                    {
                        if( $key == "to" || $key == "from")
                            continue;
                        if( $key == "daily" )
                        {
                            $tmp_schedule->setRecurringDaily( $scheduleWeekly['from']."-".$scheduleWeekly['to'] );
                        }
                        else
                        {
                            /** @var Schedule $tmp_schedule */
                            print $key."@".$scheduleWeekly['from']."-".$scheduleWeekly['to']."\n";
                            $tmp_schedule->setRecurringWeekly( $key, $scheduleWeekly['from']."-".$scheduleWeekly['to'] );
                        }

                    }
                }
                elseif( $scheduleEntryabsoluteFound )
                {
                    $addlog = "time-range absolute already added - this can not be added: " . $names_line;
                    $tmp_schedule->set_node_attribute('warning', $addlog);

                }
                elseif( $scheduleEntryperiodicFound )
                {
                    $addlog = "time-range periodic already added - this can not be added: " . $names_line;
                    $tmp_schedule->set_node_attribute('warning', $addlog);

                }
            }

            if( preg_match("/^time-range/i", $names_line) )
            {

                print "\n\n";

                $isTimeRange = 1;
                $scheduleEntryabsoluteFound = false;
                $scheduleEntryperiodicFound = false;

                $names = explode(" ", $names_line);
                $TimeRangeName = rtrim($names[1]);
                $TimeRangeNamePan = $this->truncate_names($this->normalizeNames($TimeRangeName));

                //Todo: create object
                $tmp_schedule = $this->sub->scheduleStore->find($TimeRangeNamePan);
                if( $tmp_schedule === null )
                {
                    if( $print )
                        print "\n * create schedule object: " . $TimeRangeNamePan . "\n";
                    $tmp_schedule = $this->sub->scheduleStore->createSchedule( $TimeRangeNamePan );
                }
                else
                {
                    $addlog = "time-range object already available - this can not be added: " . $names_line;
                    $tmp_schedule->set_node_attribute('warning', $addlog);
                }
            }
        }
    }
}