<?php
/**
 * Custom authentication for Diabetes Qualified project
 *
 * Local library functions
 *
 * @package    auth_dq
 * @author     Ken Chang <kenc@pukunui.com>, Pukunui
 * @copyright  2018 onwards, Pukunui
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

define("DQ_PRE_SHAREDKEY", "Hello world.");
// define("DQ_PRIVATEKEY", "dq_private");

/**
 * Return an html table with a list of cpd log entries
 *
 * @return html_table
 */
function auth_dq_get_cpdlog_table($page) {
    global $DB, $USER, $OUTPUT;
/*
    $table = new html_table();

    if ($cpdlog = $DB->insert_record('auth_dq_cpdlog', $cpdlog))) {

        $table->head  = array(get_string('cpdlog:table:th:name', 'auth_dq'),
                                get_string('cpdlog:table:th:email', 'auth_dq'),
                                get_string('cpdlog:table:th:course', 'auth_dq'),
                                get_string('cpdlog:table:th:points', 'auth_dq'));
                                get_string('cpdlog:table:th:timestarted', 'auth_dq'));
                                get_string('cpdlog:table:th:timefinished', 'auth_dq'));
        $table->align = array('left', 'left', 'left', 'left', 'left', 'left');

        foreach ($cpdlog as $cpd) {

            $editlink = new moodle_url('/user/view.php', array('id' => $cpd->userid));
            $classlink = new moodle_url('/course/index.php', array('id' => $cpd->courseid));

            $row = new html_table_row();

            $row->cells[] = new html_table_cell(html_writer::link($editlink, $cpd->firstname.' '.$cpd->lastname));
            $row->cells[] = $cpd->email;
            $row->cells[] = new html_table_cell(html_writer::link($classlink, $cpd->classname));
            $row->cells[] = $cpd->cpdpoints;
            $row->cells[] = date('d/m/Y', $cpd->timestarted);
            $row->cells[] = date('d/m/Y', $cpd->timefinished);

            $table->data[] = $row;
        }
    }
    return $table;
    */
}

/**
  * Write the CSV output to file
  *
  * @param string $csv  the csv data
  * @return boolean  success?
*/
function auth_dq_cpdlog() {

    global $CFG, $DB;

    $runnow = time(); // - (60*3); // minus 3 minutes for delays
//    echo $runnow;
    $config = get_config('auth_dq');
//echo 'config: ';
//print_object($config);
    require_once($CFG->libdir . '/filelib.php');

    //-- Get token ----------------------------------------------------------------------------------------------
    // Sending the request access key request to membes.

    $header = array('Accept: application/json', 'X-AN-APP-NAME: ' . $config->oauthcpdlogappname, 'X-AN-APP-KEY: none');
    $token = '';

    // The token lasts for an hour, but as a margin for error, will only be used for 58 minutes.
//echo $config->oauthcpdlogtokenexpiry. ' < '.(time() - (60*58)).'<br><br>';
    if ($config->oauthcpdlogtokenexpiry < time() - (60*58)) {

        // We use an APP Key "none", it can be anything.

        $curl = new curl();
        $curl->setHeader($header);

        $params = array(
                    'client_id' => $config->oauthclientid,
                    'client_secret' => $config->oauthclientsecret,
        );
//echo 'params: ';
//print_object($params);

        $response = $curl->post($config->oauthcpdlogtokenurl, $params);
//echo 'response: ';
//print_object($response);

        if ($key = json_decode($response, true)) {
//print_object($key);

            $token = (!empty($key['TOKEN'])) ? $key['TOKEN'] : '';
            $status = (!empty($key['STATUS'])) ? $key['STATUS'] : false;

            if (!empty($key['MESSAGE'])) {
                if ($key['MESSAGE'] == 'Invalid Token.') throw new coding_exception("Invalid Token.");
            }
        }
        set_config('oauthcpdlogtoken', $token, 'auth_dq');
    } else {
        $token = $config->oauthcpdlogtoken;
    }


// echo 'token: '.$token.'<br><br>';
    //-- Get course completion information from the database ----------------------------------------------------

    $params = array('timecompleted' => $config->oauthcpdloglastrun, 'timefinished' => $runnow, 'runnow' => $runnow);
//echo 'params: ';
//print_object($params);

    $sql = "
       SELECT adc.id, adc.userid, adc.email, c.shortname as coursename, adc.cpdpoints, cc.timecompleted
       FROM {auth_dq_cpdlog} AS adc
       JOIN {course} as c ON adc.courseid = c.id
       JOIN {course_completions} AS cc ON cc.userid = adc.userid AND cc.course = adc.courseid
       WHERE cc.timecompleted IS NOT NULL
       AND cc.timecompleted BETWEEN :timecompleted AND :runnow
       AND adc.timefinished <= :timefinished
    ";
    /*
    $sql = "
       SELECT adc.id, adc.userid, adc.email, adc.cpdpoints, c.shortname as coursename, cc.timecompleted
       FROM mdl_auth_dq_cpdlog AS adc
       JOIN mdl_course as c ON adc.courseid = c.id
       JOIN mdl_course_completions AS cc ON cc.userid = adc.userid AND cc.course = adc.courseid
       WHERE cc.timecompleted IS NOT NULL
       AND cc.timecompleted BETWEEN 0 AND UNIX_TIMESTAMP()
       AND adc.timefinished <= UNIX_TIMESTAMP()
    ";
*/
// print_object('sql:'.$sql);
    $cpdlog = $DB->get_records_sql($sql, $params);

//echo 'cpdlog array: ';
//print_object($cpdlog);

    //-- Send updated records to DQ ----------------------------------------------------------------------------

    foreach ($cpdlog as $cpdentry)
    {
        $curl           = new curl();
        $curl->setHeader($header);

        $curl->setopt(array('CURLOPT_CUSTOMREQUEST' => 'POST'));
        $curl->setopt(array('CURLOPT_RETURNTRANSFER' => true));

        $hours = 0;

        $params = array(
                    'token' => $token,
                    'email' => $cpdentry->email,
                    'name' => $cpdentry->coursename,
                    'categoryid' => $config->oauthcpdlogcategoryid,
                    'activityid' => $config->oauthcpdlogactivityid,
                    'date' => $cpdentry->timecompleted,
                    'points' => $cpdentry->cpdpoints,
                    'hours' => $hours,
                );
//echo 'params: ';
// print_object($params);

        $response = $curl->post($config->oauthcpdlogtokenurl, $params);
//echo 'response: ';
//print_object($response);

        if ($key = json_decode($response, true)) {
            $status = (!empty($key['STATUS'])) ? $key['STATUS'] : false;
            $message = (!empty($key['MESSAGE'])) ? $key['MESSAGE'] : '';
            $data = (!empty($key['DATA'])) ? $key['DATA'] : null;
        }
        if ($status)
        {
            mtrace("CPD Acivity Log entry has been saved. ID: ".$cpdentry->id);
        }
    }

    //-- Validate the response to the request -------------------------------------------------------------------

    $params = array('lastrun' => intval($config->oauthcpdloglastrun) - (60*3), 'runnow' => $runnow);

    $sql = "
        UPDATE {auth_dq_cpdlog} AS adc, {course_completions} AS cc
        SET adc.timefinished = cc.timecompleted
        WHERE adc.userid = cc.userid AND adc.courseid = cc.course
        AND cc.timecompleted BETWEEN :lastrun AND :runnow
    ";
/*
    $sql = "
        UPDATE mdl_auth_dq_cpdlog AS adc, mdl_course_completions AS cc
        SET adc.timefinished = cc.timecompleted
        WHERE adc.userid = cc.userid AND adc.courseid = cc.course
        AND cc.timecompleted BETWEEN 0 AND UNIX_TIMESTAMP()
    ";

*/

    $DB->execute($sql, $params);

    set_config('oauthcpdloglastrun', $runnow, 'auth_dq');
}
