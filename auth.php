<?php
/**
 * Custom authentication for Diabetes Qualified project
 * Ticket number ARN-716543
 * Authentication class
 *
 * @package    auth_dq
 * @author     Ken Chang <kenc@pukunui.com>, Pukunui
 * @copyright  2018 onwards, Pukunui
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

/**
 * Diabetes Qualified authentication class
 */
class auth_plugin_dq extends auth_plugin_base {

    /**
     * Constructor.
     */
    public $loginform;
    public $signupform;

    public function __construct() {
        $this->authtype = 'dq';
        $this->config = get_config('auth/dq');
    }
    /**
     * Update a user session
     *
     * @return true
     */
    public function update_user_session($u) {

        global $USER;

        // Override old $USER session variable.
        foreach ((array)$u as $variable => $value) {
            if ($variable === 'description' or $variable === 'password') {
                // These are not set for security and perf reasons.
                continue;
            }
            $USER->$variable = $value;
        }
        return true;
    }

    /**
     * Return a form to log into a user account
     * This is used in /login/signup.php
     *
     * @return moodle_form  a form which edits a record from the user table
     */
    public function login_form($loginurl) {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_login_form($loginurl, null, 'post', '', array('autocomplete' => 'on'));
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {
        global $CFG, $DB;
        if ($user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id))) {
            return validate_internal_user_password($user, $password);
        }
        return false;
    }

    /**
     * Updates the user's password.
     *
     * called when the user password is updated.
     *
     * @param  object  $user        User table object  (with system magic quotes)
     * @param  string  $password Plaintext password (with system magic quotes)
     * @return boolean result
     *
     */
    public function user_update_password($user, $password) {
        $user = get_complete_user_data('id', $user->id);
        // This will also update the stored hash to the latest algorithm if the existing hash is using an out-of-date
        // algorithm (or the legacy md5 algorithm).
        return update_internal_user_password($user, $password);
    }

    public function can_signup() {
        return true;
    }

    /**
     * Sign up a new user ready for confirmation.
     * Password is passed in plaintext.
     *
     * @param object $user new user object
     * @param boolean $notify print notice with link and terminate
     */
    public function user_signup($user, $notify=true) {
        global $CFG, $DB;
        require_once($CFG->dirroot.'/user/profile/lib.php');
        require_once($CFG->dirroot.'/user/lib.php');

        $plainpassword = $user->password;
        $user->password = hash_internal_user_password($user->password);
        $user->mnethostid = $CFG->mnet_localhost_id;

        if (empty($user->secret)) {
            $user->secret = '';
        }
        if (empty($user->calendartype)) {
            $user->calendartype = $CFG->calendartype;
        }

        $firstname = strtolower($user->firstname);
        $lastname = strtolower($user->lastname);
        $initials = $firstname[0].$lastname[0];

        try {
            $transaction = $DB->start_delegated_transaction();

            do {
                $username = sprintf($initials."%04d", rand (1 , 9999));
            } while ($DB->get_record('user', array("username" => $username), 'id', IGNORE_MISSING));

            $user->username = $username;
            $userdetailstext = "Username: $username<br />Password: $plainpassword";

            $user->id = user_create_user($user, false, false);

            user_add_password_history($user->id, $plainpassword);

            // Save any custom profile field information.

            $user->profile_field_typeofaccount = empty($user->profile_field_typeofaccount) ? 'student' : $user->profile_field_typeofaccount;
            $user->profile_field_yearlevel = empty($user->profile_field_yearlevel) ? 'N/A' : $user->profile_field_yearlevel;
            $user->profile_field_yearofbirth = empty($user->profile_field_yearofbirth) ? 'N/A' : $user->profile_field_yearofbirth;
            $user->profile_field_whereareyoufrom = empty($user->profile_field_whereareyoufrom) ? 'Perth' : $user->profile_field_whereareyoufrom;

            profile_save_data($user);

            // Trigger event.
            \core\event\user_created::create_from_userid($user->id)->trigger();

             // Assuming the both inserts work, we get to the following line.
             $transaction->allow_commit();

        } catch (Exception $e) {
             $transaction->rollback($e);
             return false;
        }

        if (!send_confirmation_email($user)) {
            print_error('auth_emailnoemail, auth_email');
        }

        if ($notify) {
            global $CFG, $PAGE, $OUTPUT;
            $emailconfirm = get_string('emailconfirm');
            $PAGE->navbar->add($emailconfirm);
            $PAGE->set_title($emailconfirm);
            $PAGE->set_heading($PAGE->course->fullname);
            echo $OUTPUT->header();

            notice(get_string('signup:emailconfirmsent:text', 'auth_dq', $userdetailstext), "$CFG->wwwroot/index.php");
        } else {
            return true;
        }
    }

    /**
     * Update details for the current user
     * Password is passed in plaintext.
     *
     * @param object $user current user object
     * @param boolean $notify print notice with link and terminate
     */
    public function user_update_details($user) {

        global $CFG, $DB, $USER;

        require_once($CFG->dirroot.'/user/profile/lib.php');
        require_once($CFG->dirroot.'/user/lib.php');

        if ($user->password == $user->confirmpassword and !empty($user->password)) {
            $plainpassword = $user->password;

        echo $plainpassword;
            $user->password = hash_internal_user_password($user->password);
            $this->user_update_password($user, $user->password);
            user_add_password_history($user->id, $plainpassword);
        }
        if (empty($user->calendartype)) {
            $user->calendartype = $CFG->calendartype;
        }
        try {
            $transaction = $DB->start_delegated_transaction();

            user_update_user($user, false, false);

            $user->profile_field_yearlevel = empty($user->profile_field_yearlevel) ? 'N/A' : $user->profile_field_yearlevel;
            $user->profile_field_yearofbirth = empty($user->profile_field_yearofbirth) ? 'N/A' : $user->profile_field_yearofbirth;
            $user->profile_field_whereareyoufrom = empty($user->profile_field_whereareyoufrom) ? 'Perth' : $user->profile_field_whereareyoufrom;

            $USER->profile['yearlevel'] = $user->profile_field_yearlevel;
            $USER->profile['yearofbirth'] = $user->profile_field_yearofbirth;
            $USER->profile['whereareyoufrom'] = $user->profile_field_whereareyoufrom;

            profile_save_data($user);

            // Trigger event.
            \core\event\user_updated::create_from_userid($user->id)->trigger();
             // Assuming the both inserts work, we get to the following line.
             $transaction->allow_commit();

        } catch (Exception $e) {
             $transaction->rollback($e);
             return false;
        }

        return $this->update_user_session($user);
    }

    /**
     * Returns true if plugin allows confirming of new users.
     *
     * @return bool
     */
    public function can_confirm() {
        return true;
    }

    /**
     * Confirm the new user as registered.
     *
     * @param string $username
     * @param string $confirmsecret
     */
    public function user_confirm($username, $confirmsecret) {
        global $DB;
        $user = get_complete_user_data('username', $username);

        if (!empty($user)) {
            if ($user->auth != $this->authtype) {
                return AUTH_CONFIRM_ERROR;

            } else if ($user->secret == $confirmsecret && $user->confirmed) {
                return AUTH_CONFIRM_ALREADY;

            } else if ($user->secret == $confirmsecret) {
                // They have provided the secret key to get in.
                $DB->set_field("user", "confirmed", 1, array("id" => $user->id));
                return AUTH_CONFIRM_OK;
            }
        } else {
            return AUTH_CONFIRM_ERROR;
        }
    }

    public function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    public function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    public function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    public function change_password_url() {
        // Use default internal method.
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    public function can_reset_password() {
        return true;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    public function can_be_manually_set() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    public function config_form($config, $err, $userfields) {
        include("config.html");
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    public function process_config($config) {
        // Set to defaults if undefined.
        if (!isset($config->recaptcha)) {
            $config->recaptcha = false;
        }

        // Save settings.
        set_config('recaptcha', $config->recaptcha, 'auth/dq');
        return true;
    }

    /**
     * Returns whether or not the captcha element is enabled, and the admin settings fulfil its requirements.
     * @return bool
     */
    public function is_captcha_enabled() {
        global $CFG;
        return isset($CFG->recaptchapublickey) &&
                isset($CFG->recaptchaprivatekey) &&
                get_config("auth/{$this->authtype}", 'recaptcha');
    }

    /**
     * Return a form to capture user details for account creation
     * This is used in /login/signup.php
     *
     * @return moodle_form  a form which edits a record from the user table
     */
    public function signup_form() {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_signup_form(null, null, 'post', '', array('autocomplete' => 'on'));
    }
    /**
     * Return a form to capture user details for account creation
     * This is used in /login/signup.php
     *
     * @return moodle_form  a form which edits a record from the user table
     */
    public function updateuser_form() {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_updateuser_form(null, null, 'post', '', array('autocomplete' => 'on'));
    }






    /**
     * Return a form to capture user details for account creation
     * This is used in /login/signup.php
     *
     * @return moodle_form  a form which edits a record from the user table
     */
    public function classessectionform() {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_manage_classes_section(null, null, 'post', '', array('autocomplete' => 'on'));
    }


    /**
     * Return a form to add/update/delete a class
     *
     * @return moodle_form a form which edits a record from the class table
     */
    public function classform($url, $id) {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_classform($url, $id, 'post', '', array('autocomplete' => 'on'));
    }


    /**
     * Links to add a student and a a group of students
     *
     * @return moodle_form a form which links to other pages
     */
    public function studentlistform($url, $teacherid) {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_manage_students_classes_section($url, $teacherid, 'post', '', array('autocomplete' => 'on'));
    }



    /**
     * Links to add a student and a a group of students
     *
     * @return moodle_form a form which links to other pages
     */
    public function upload_import_file($url, $teacherid) {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_import_students_section($url, $teacherid, 'post', '', array('autocomplete' => 'on'));
    }








    /**
     * List all students for a teacher
     *
     * @return table that has a list of all students for a teacher ordered by class name
     */
    public function listofallstudents($teacherid) {
        global $CFG;

        require_once($CFG->dirroot.'/auth/dq/locallib.php');

        return auth_dq_get_student_class_table($teacherid);
    }



    /**
     * List all classes a student is in of a teacher
     *
     * @return table that has a list of all students for a teacher ordered by class name
     */
    public function deletefromclasseslist($delclass) {
        global $DB;
/*
            JOIN {auth_dq_student} AS ads ON ads.studentuserid = adsc.studentuserid
            JOIN {user} AS u ON u.id = ads.studentuserid
*/
        $sql = '
            SELECT adsc.id, adsc.classid, adc.name AS classname
            FROM {auth_dq_teacher} AS adt
            JOIN {auth_dq_class} AS adc ON adc.teacheruserid = adt.teacheruserid
            JOIN {auth_dq_studclass} AS adsc ON adsc.classid = adc.id
            WHERE adt.teacheruserid = :teacheruserid
            AND adsc.studentuserid = :studentuserid
        ';

        $params = array('teacheruserid' => $delclass->teacheruserid, 'studentuserid' => $delclass->studentuserid);

        if (!empty($delclass->classid)) {
            $sql .= 'AND adsc.classid = :classid';
            $params['classid'] = $delclass->classid;
        }

        if ($class = $DB->get_records_sql($sql, $params)) {
            return $class;
        }
        return false;
    }
    /**
     * For for deleting a student from a class
     *
     * @return table that has a list of all students for a teacher ordered by class name
     */
    public function deletefromclassesform($url, $deleteclasslist, $classinfo) {
        global $CFG;

        $params = $arrayName = array('deleteclasslist' => $deleteclasslist, 'classinfo' => $classinfo);

        require_once($CFG->dirroot.'/auth/dq/forms.php');

        return new auth_dq_delete_student_from_class($url, $params, 'post', '', array('autocomplete' => 'on'));
    }






















    /**
     * Add a new teacher.
     *
     * @param int teacheruserid
     */
    public function add_teacher($teacheruserid) {
        global $DB;

        $newteacher = new stdClass();
        $newteacher->teacheruserid = $teacheruserid;

        if (!($DB->insert_record('auth_dq_teacher',  $newteacher))) {
            $strcontinue = get_string('db:teacher:insert:success', 'auth_dq');
        } else {
            $strcontinue = get_string('db:teacher:insert:error', 'auth_dq');
        }
        return $strcontinue;
    }
    /**
     * Delete a teacher.
     *
     * @param int teacheruserid
     */
    public function remove_teacher($teacheruserid) {
        global $DB;

        if (!($DB->delete_records('auth_dq_teacher', array("teacheruserid" => $teacheruserid)))) {
            return false;
        }
        return true;
    }
    /**
     * Add a new student.
     *
     * @param int studentuserid
     * @param string name
     */
    public function add_student($studentuserid) {
        global $DB;

        $newstudent = new stdClass();
        $newstudent->studentuserid = $studentuserid;

        if (!($DB->insert_record('auth_dq_student',  $newstudent))) {
            return false;
        }
        return true;
    }
    /**
     * Delete a student.
     *
     * @param int studentuserid
     */
    public function remove_student($studentuserid) {
        global $DB;

        if (!($DB->delete_records('auth_dq_student', array("studentuserid" => $studentuserid)))) {
            return false;
        }
        return true;
    }
    /**
     * Add a new class.
     *
     * @param int teacheruserid
     * @param string name
     */
    public function add_class($teacheruserid, $name) {
        global $DB;

        $strcontinue = '';

        $addparams = new stdClass();
        $addparams->teacheruserid = $teacheruserid;
        $addparams->name = $name;

        if ($classid = $DB->insert_record('auth_dq_class',  $addparams)) {
          //  $strcontinue = get_string('db:class:insert:success', 'auth_dq');

        } else {
          //  $strcontinue = get_string('db:class:insert:error', 'auth_dq');
            $classid = 0;
        }
        return $classid;
    }
    /**
     * Update a class.
     *
     * @param int classid
     * @param int teacheruserid
     * @param string name
     */
    public function update_class_name($classid, $name) {
        global $DB;

        $updateparams = new stdClass();
        $updateparams->id = $classid;
        $updateparams->name = $name;

        if ($DB->update_record('auth_dq_class', $updateparams)) {
            $strcontinue = get_string('db:class:update:success', 'auth_dq');
        } else {
            $strcontinue = get_string('db:class:update:error', 'auth_dq');
        }
        return $strcontinue;
    }
    /**
     * Remove a class.
     *
     * @param int teacheruserid
     * @param string name
     */
    public function remove_class($id) {
        global $DB;

        if ($DB->delete_records('auth_dq_class', array("id" => $id))) {
            $strcontinue = get_string('db:class:delete:success', 'auth_dq');
        } else {
            $strcontinue = get_string('db:class:delete:error', 'auth_dq');
        }
        return $strcontinue;
    }
    /**
     * Remove all of one teacher's classes.
     *
     * @param int teacheruserid
     */
    public function remove_teacher_classes($removeclasses, $confirmsecret) {
        global $DB;

        if (!($DB->delete_records('auth_dq_class', array("teacheruserid" => $teacheruserid)))) {
            return false;
        }
        return true;
    }
    /**
     * Add student to class.
     *
     * @param int classid
     * @param int studentuserid
     */
    public function add_student_class($classid, $studentuserid) {
        global $DB;

        $studclass = new stdClass();
        $studclass->classid = $classid;
        $studclass->studentuserid = $studentuserid;

        if (!($DB->insert_record('auth_dq_studclass',  $studclass))) {
            return false;
        }
        return true;
    }
    /**
     * Remove student to class.
     *
     * @param int classid
     * @param int studentuserid
     */
    public function remove_student_class($classid, $studentuserid) {
        global $DB;

        if ($DB->delete_records('auth_dq_studclass', array("classid" => $classid, "studentuserid" => $studentuserid))) {
            $strcontinue = get_string('db:class:delete:success', 'auth_dq');
        } else {
            $strcontinue = get_string('db:class:delete:error', 'auth_dq');
        }
        return $strcontinue;
    }
}


