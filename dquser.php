<?php
/**
 * Custom authentication for Diabetes Qualified project login/signup page
 * Ticket number ARN-716543
 * @package    auth_dq
 * @author     Ken Chang <kenc@pukunui.com>, Pukunui
 * @copyright  2018 onwards, Pukunui
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once('./locallib.php');
require_once('./auth.php');
require_once($CFG->dirroot.'/user/lib.php');
require_once($CFG->dirroot.'/admin/tool/log/store/standard/classes/log/store.php');

$systemcontext = context_system::instance();
$strpluginname = get_string('pluginname', 'auth_dq');
$returnurl = "/auth/dq/dquser.php";
$title = get_string('enroluser:metatag:heading', 'auth_dq');

$PAGE->set_context($systemcontext);
$PAGE->set_title($title);
$PAGE->set_heading($title);
$PAGE->set_pagelayout('standard');
$PAGE->set_url($returnurl);

//get values from urls string
$username       = required_param('username', PARAM_TEXT);
$timestamp      = required_param('timestamp', PARAM_INT);
$hash           = required_param('hash', PARAM_ALPHANUM);
$firstname      = optional_param('firstname','', PARAM_TEXT);
$lastname       = optional_param('lastname','', PARAM_TEXT);
$email          = optional_param('email', '',PARAM_EMAIL);
$coursename     = optional_param('course', '', PARAM_TEXT);
//get the stored timestamp from config(in the settings.php you can see the stored timestamp)
$config         = get_config('auth_dq');
/*
https://ken.test.pukunui.net/auth/dq/dquser.php?
username=kenwest&
timestamp=1532919251&
hash=A592149E972C5E1A01976DD277EAC27B&
firstname=kenwaa&
lastname=eest&
email=kenwest@nomail.com&
course=test101
*/
/*
https://dqnsw.moodlesite.pukunui.net/auth/dq/dquser.php?
username=pukunuitest&
timestamp=1532924176&
hash=52A5E01B665DC803C40D496619A90DBE&
firstname=pukunuitt&
lastname=user01&
email=pukunuitest@nomail.com&
course=Webinar: Role of fibre
*/

$userid         = 0;
$ueid           = 0;
$raid           = 0;
$out            = '';
$enrolrequest   = new auth_plugin_dq;

$jsonoutput = array();

$converttotimestamp = strtotime(get_config('auth_dq', 'lasttimestamptodate'));

//if ($timestamp > $converttotimestamp) //current timestamp is bigger than the stored one
if($timestamp > 0) // Test
{
    $from = get_admin(); //Ask boss
    $modifier = $DB->get_record('user', array('id' => $from->id)); //Ask boss about the $modifier and the id, I think it's something about Admin enrol user to the course

    //(!preg_match(/^[_0-9a-zA-Z]{3,12}$/i,$nicker)) //ex

    //Username can not includes uppercase letters, but can using email to be their username
    $checkstr1 = "/^([0-9a-z]+)$/";
    $checkstr2 = "/^[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)+$/";

    //Check the username string
    if (preg_match($checkstr1,$username) || preg_match($checkstr2,$username))
    {
        // Everytime no matter what they try to insert/update the user to database, will save the successfully record's timestamp in the config
        // This method can make sure next timestamp must bigger than current one, otherwise will block them
        // save timestamp
        set_config('lasttimestamptodate', date('d-m-Y H:i:s', $timestamp), 'auth_dq');

        //Force all the md5 string to be3 lowercase letters
        if (strtolower(md5($username.$timestamp.DQ_PRE_SHAREDKEY)) == strtolower($hash))
        { 
            $user                   = null;
            $userdata               = new stdClass();
            $userdata->username     = $username;
            $userdata->firstname    = $firstname;
            $userdata->lastname     = $lastname;
            $userdata->email        = $email;
            $userdata->mnethostid   = 1;
            $password               = generate_password();

            //username exists
            if ($user = $DB->get_record('user', array('auth' => 'manual','username' => $username)))
            {
                //Pass the user id record to $getuserid and then I can use it inside the sql search query " "
                $getuserid = $user->id;

                //Check the passed passed $email string, go to database to see if this email already exists 
                $duplicateemail = "SELECT u.id
                                   FROM {user} u
                                   WHERE u.auth = 'manual'
                                   AND u.email = '$email'
                                   AND u.id <> '$getuserid'";
                $emailresult = $DB->get_records_sql($duplicateemail);

                //Duplicated user email in database
                if ($emailresult)
                {
                    //display messages
                    $jsonoutput['message'] = 'This email address is already in use for another user';
                    $jsonoutput['status'] = 'Failed';
                }
                else 
                {
                    // if the firsname or lastname or email are different also the email is not duplicated
                    // We will know they want to update the information for the user 
                    if ((($firstname != $user->firstname) || 
                         ($lastname  != $user->lastname)  ||
                         ($email     != $user->email)) && !$emailresult) 
                    {
                        // validate the passed string fields
                        // if the sting is blank, I won't updated it, I will use the data in the database to update it
                        if (trim($firstname)) { //if the string is not blank and clean the front and end spaces for the string
                            $userdata->firstname     = trim($firstname);
                        } else {
                            $userdata->firstname     = $user->firstname;
                        }
                        if (trim($lastname)) {
                            $userdata->lastname     = trim($lastname);
                        } else {
                            $userdata->lastname     = $user->lastname;
                        }
                        if (trim($email)) {
                            $userdata->email     = trim($email);
                        } else {
                            $userdata->email     = $user->email;
                        }

                        // Update old user with new user details.
                        $userdata->id           = $user->id;
                        user_update_user($userdata, false, false);

                        $userid                 = $user->id;
                        $password = 'Not Changed';

                        $user = $DB->get_record('user', array('id' => $userid));

                        $auth = get_auth_plugin($user->auth);

                        if (!($result = $auth->user_confirm($user->username, $user->secret))) 
                        {
                            throw new coding_exception(get_string('user:confirm:fail', 'auth_dq'));
                        }
                        $jsonoutput['userid'] = $userid;
                        $jsonoutput['message'] = 'Updated user profile';
                        $jsonoutput['status'] = 'Success';

                        // If they passed course name,I will check is this course name exist and then redirect user to specific course
                        if(!$coursename) // non course shortname provide
                        {
                            complete_user_login($user);
                            redirect($CFG->wwwroot); //Go to Dashboard
                        } 
                        else 
                        {
                            //Check the course shortname is existed in the database or not
                            $checkcoursesql = "SELECT c.id,c.shortname,c.fullname
                                               FROM {course} c
                                               WHERE c.shortname = '$coursename'";

                            $coursefields = $DB->get_record_sql($checkcoursesql);

                            if (!$coursefields) // course is not exists
                            {
                                $jsonoutput['message'] = 'Course short name does not exist1';
                                $jsonoutput['status'] = 'Failed';
                            } 
                            else 
                            {
                                $jsonoutput['courseid'] = $coursefields->id;
                                $jsonoutput['shortname'] = $coursefields->shortname;
                                $jsonoutput['message'] = 'Course existed!';
                                $jsonoutput['status'] = 'Success';
                                
                                //Check the student is enroled in the course or not
                                $enrol = $DB->get_record('enrol', array('courseid' => $coursefields->id, 'enrol' => 'manual'));

                                $userenrolment                  = new stdClass();
                                $userenrolment->enrolid         = $enrol->id;
                                $userenrolment->userid          = $getuserid;
                                $userenrolment->modifierid      = $modifier->id;
                                $userenrolment->timestart       = time();
                                $userenrolment->timeend         = 0;
                                $userenrolment->timecreated     = time();
                                $userenrolment->timemodified    = time();

                                // User not enroled in this course
                                if (!($ue = $DB->get_record('user_enrolments', array('userid' => $getuserid, 'enrolid' => $enrol->id))))
                                {
                                    // Enrol the student and shows them the message
                                    $jsonoutput['message'] = ($ueid = $DB->insert_record('user_enrolments', $userenrolment)) ? 'You are enrolled in '.$coursefields->fullname : 'You were not enrolled in a course';
                                    // $out .= html_writer::div(($ueid = $DB->insert_record('user_enrolments', $userenrolment)) ? 'You are enrolled in '.$course->fullname : 'You were not enrolled in a course');
                                }
                                else 
                                {
                                    // shows them already been enrolled in this course
                                    $jsonoutput['message'] = 'You are enrolled in '.$coursefields->fullname;
                                    // $out .= html_writer::div('You are enrolled in '.$course->fullname);
                                    // $ueid = $ue->id;
                                }

                                //Assign the user to be the student role
                                $coursecontext                  = context_course::instance($coursefields->id);
                                $roleassignment                 = new stdClass();
                                $roleassignment->roleid         = 5;
                                $roleassignment->contextid      = $coursecontext->id;
                                $roleassignment->userid         = $getuserid;
                                $roleassignment->component      = 'auth_dq';
                                $roleassignment->itemid         = 0;
                                $roleassignment->timemodified   = time();
                                $roleassignment->modifierid     = $modifier->id;
                                $roleassignment->sortorder      = 0;

                                //User not enroled in this course
                                if (!($ra = $DB->get_record('role_assignments', array('userid' => $getuserid, 'roleid' => 5, 'contextid' => $coursecontext->id, 'modifierid' => $modifier->id))))
                                {
                                    $jsonoutput['role'] = ($raid = $DB->insert_record('role_assignments', $roleassignment)) ? 'You have the role of a student' : 'You have no role';
                                    // $out .= html_writer::div(($raid = $DB->insert_record('role_assignments', $roleassignment)) ? 'You have the role of a student' : 'You have no role');
                                } else {
                                    $jsonoutput['role'] = 'You have the role of a student';
                                    // $out .= html_writer::div('You have the role of a student');
                                    // $raid = $ra->id;
                                }

                                complete_user_login($user);
                                redirect($CFG->wwwroot."/course/view.php?id=".$coursefields->id); // redirect the user to specific course
                            }
                        }
                    }
                    // if the firsname or lastname or email are different also the email did not changed and the email is not duplicated
                    // We will know they want to let the user login
                    elseif ((($firstname == $user->firstname) && 
                             ($lastname  == $user->lastname) &&
                             ($email     == $user->email)) && !$emailresult)
                    {
                        
                        if(!$coursename) //non course shortname provide
                        {
                            complete_user_login($user);
                            redirect($CFG->wwwroot); //Go to Dashboard
                        }
                        else 
                        {
                            //Check the course shortname
                            $checkcoursesql = "SELECT c.id,c.shortname,c.fullname
                                               FROM {course} c
                                               WHERE c.shortname = '$coursename'";

                            $coursefields = $DB->get_record_sql($checkcoursesql);

                            if (!$coursefields) //course is not exists
                            {
                                $jsonoutput['message'] = 'Course short name does not exist';
                                $jsonoutput['status'] = 'Failed';
                            }
                            else
                            {
                                $jsonoutput['courseid'] = $coursefields->id;
                                $jsonoutput['shortname'] = $coursefields->shortname;
                                $jsonoutput['message'] = 'Course existed!';
                                $jsonoutput['status'] = 'Success';

                                //Check the student is enroled in the course or not
                                $enrol = $DB->get_record('enrol', array('courseid' => $coursefields->id, 'enrol' => 'manual'));
                                $userenrolment                  = new stdClass();
                                $userenrolment->enrolid         = $enrol->id;
                                $userenrolment->userid          = $getuserid;
                                $userenrolment->modifierid      = $modifier->id;
                                $userenrolment->timestart       = time();
                                $userenrolment->timeend         = 0;
                                $userenrolment->timecreated     = time();
                                $userenrolment->timemodified    = time();

                                if (!($ue = $DB->get_record('user_enrolments', array('userid' => $getuserid, 'enrolid' => $enrol->id)))) //User not enroled in this course
                                {
                                    $jsonoutput['message'] = ($ueid = $DB->insert_record('user_enrolments', $userenrolment)) ? 'You are enrolled in '.$coursefields->fullname : 'You were not enrolled in a course';
                                    // $out .= html_writer::div(($ueid = $DB->insert_record('user_enrolments', $userenrolment)) ? 'You are enrolled in '.$course->fullname : 'You were not enrolled in a course');
                                }
                                else
                                {
                                    $jsonoutput['message'] = 'You are enrolled in '.$coursefields->fullname;
                                    // $out .= html_writer::div('You are enrolled in '.$course->fullname);
                                    // $ueid = $ue->id;
                                }

                                //Assign the user to be the student role
                                $coursecontext                  = context_course::instance($coursefields->id);
                                $roleassignment                 = new stdClass();
                                $roleassignment->roleid         = 5;
                                $roleassignment->contextid      = $coursecontext->id;
                                $roleassignment->userid         = $getuserid;
                                $roleassignment->component      = 'auth_dq';
                                $roleassignment->itemid         = 0;
                                $roleassignment->timemodified   = time();
                                $roleassignment->modifierid     = $modifier->id;
                                $roleassignment->sortorder      = 0;

                                if (!($ra = $DB->get_record('role_assignments', array('userid' => $getuserid, 'roleid' => 5, 'contextid' => $coursecontext->id, 'modifierid' => $modifier->id))))
                                {
                                    $jsonoutput['role'] = ($raid = $DB->insert_record('role_assignments', $roleassignment)) ? 'You have the role of a student' : 'You have no role';
                                    // $out .= html_writer::div(($raid = $DB->insert_record('role_assignments', $roleassignment)) ? 'You have the role of a student' : 'You have no role');
                                }
                                else
                                {
                                    $jsonoutput['role'] = 'You have the role of a student';
                                    // $out .= html_writer::div('You have the role of a student');
                                    //$raid = $ra->id;
                                }
                                complete_user_login($user);
                                redirect($CFG->wwwroot."/course/view.php?id=".$coursefields->id); // redirect the user to specific course
                            }
                        }
                    }
                }
            }
            else //username is not exists, create a new account for user and enrol them to specific course if they give a course name to us
            {
                if ($firstname && $lastname && $email) // if 3 of url string are not blank or empty strings
                {
                    $emailsql = "SELECT u.id
                                 FROM {user} u
                                 WHERE u.auth = 'manual'
                                 AND u.email = '$email'";
                    $emailresult = $DB->get_records_sql($emailsql);

                    if (!$emailresult) //create user record and login
                    {
                        // Insert new user details.
                        $userdata->id           = 0;
                        $userdata->password     = hash_internal_user_password($password);
                        $userdata->confirm      = 1;
                        $userid                 = user_create_user($userdata, false, false);

                        $user = $DB->get_record('user', array('id' => $userid));

                        $auth = get_auth_plugin($user->auth);

                        if (!($result = $auth->user_confirm($user->username, $user->secret))) {
                            throw new coding_exception(get_string('user:confirm:fail', 'auth_dq'));
                        }
                        $jsonoutput['userid'] = $userid;

                            if (!$coursename) { //non course shortname provide
                                complete_user_login($user);
                                redirect($CFG->wwwroot); //Go to Dashboard
                            } else {
                                $checkcoursesql = "SELECT c.id,c.shortname,c.fullname
                                                   FROM {course} c
                                                   WHERE c.shortname = '$coursename'";

                                $coursefields = $DB->get_record_sql($checkcoursesql);
    
                                if (!$coursefields) //course is not exists
                                {
                                    $jsonoutput['message'] = 'Course short name does not exist3';
                                    $jsonoutput['status'] = 'Failed';
                                }
                                else
                                {
                                    $jsonoutput['courseid'] = $coursefields->id;
                                    $jsonoutput['shortname'] = $coursefields->shortname;
                                    $jsonoutput['message'] = 'Course existed!';
                                    $jsonoutput['status'] = 'Success';
                                    
                                    //Check the student is enroled in the course or not
                                    $enrol = $DB->get_record('enrol', array('courseid' => $coursefields->id, 'enrol' => 'manual'));

                                    $userenrolment                  = new stdClass();
                                    $userenrolment->enrolid         = $enrol->id;
                                    $userenrolment->userid          = $userid;
                                    $userenrolment->modifierid      = $modifier->id;
                                    $userenrolment->timestart       = time();
                                    $userenrolment->timeend         = 0;
                                    $userenrolment->timecreated     = time();
                                    $userenrolment->timemodified    = time();

                                    //enrol user to the specific course
                                    if (!($ue = $DB->get_record('user_enrolments', array('userid' => $userid, 'enrolid' => $enrol->id)))) //User not enroled in this course
                                    {
                                        $jsonoutput['message'] = ($ueid = $DB->insert_record('user_enrolments', $userenrolment)) ? 'You are enrolled in '.$coursefields->fullname : 'You were not enrolled in a course';
                                        // $out .= html_writer::div(($ueid = $DB->insert_record('user_enrolments', $userenrolment)) ? 'You are enrolled in '.$course->fullname : 'You were not enrolled in a course');
                                    }
                                    else
                                    {
                                        $jsonoutput['message'] = 'You are enrolled in '.$coursefields->fullname;
                                        // $out .= html_writer::div('You are enrolled in '.$course->fullname);
                                        // $ueid = $ue->id;
                                    }

                                    //Assign the user to be the student role
                                    $coursecontext                  = context_course::instance($coursefields->id);
                                    $roleassignment                 = new stdClass();
                                    $roleassignment->roleid         = 5;
                                    $roleassignment->contextid      = $coursecontext->id;
                                    $roleassignment->userid         = $userid;
                                    $roleassignment->component      = 'auth_dq';
                                    $roleassignment->itemid         = 0;
                                    $roleassignment->timemodified   = time();
                                    $roleassignment->modifierid     = $modifier->id;
                                    $roleassignment->sortorder      = 0;
                        
                                    if (!($ra = $DB->get_record('role_assignments', array('userid' => $userid, 'roleid' => 5, 'contextid' => $coursecontext->id, 'modifierid' => $modifier->id)))) {
                                        $jsonoutput['role'] = ($raid = $DB->insert_record('role_assignments', $roleassignment)) ? 'You have the role of a student' : 'You have no role';
                                  //      $out .= html_writer::div(($raid = $DB->insert_record('role_assignments', $roleassignment)) ? 'You have the role of a student' : 'You have no role');
                                    } else {
                                        $jsonoutput['role'] = 'You have the role of a student';
                                   //     $out .= html_writer::div('You have the role of a student');
                                        //$raid = $ra->id;
                                    }
                                    complete_user_login($user);
                                    redirect($CFG->wwwroot."/course/view.php?id=".$coursefields->id); // redirect the user to specific course
                                }
                            }
                    }
                    else //already had existing email record in table
                    { 
                        $jsonoutput['message'] = 'This email address is already in use for another user';
                        $jsonoutput['status'] = 'Failed';
                    }
                }
                else // $firstname or $lastname or $email is blank
                {
                    if(!$firstname) {
                        $jsonoutput['message'] = 'Username does not exist, new user must have a first name';
                    }
                    if(!$lastname) {
                        $jsonoutput['message'] = 'Username does not exist, new user must have a last name';
                    }
                    if(!$email) {
                        $jsonoutput['message'] = 'Username does not exist, new user must have an email address';
                    }
                    $jsonoutput['status'] = 'Failed';
                }
            }
        }
        else
        {
            $jsonoutput['message'] = 'Invalid Hash';
            $jsonoutput['status'] = 'Failed';
        }
    }
    else
    {
        $jsonoutput['message'] = 'Invalid characters are included in the username: A - Z';
        $jsonoutput['status'] = 'Failed';  
    }
}
else
{
    $jsonoutput['message'] = 'Invalid timestamp';
    $jsonoutput['status'] = 'Failed';
}
header('Content-Type: application/json; charset=UTF-8');
echo json_encode($jsonoutput);