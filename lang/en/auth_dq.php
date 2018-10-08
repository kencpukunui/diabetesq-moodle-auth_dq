<?php
/**
 * Custom authentication for Diabetes Qualified project
 * Ticket number ARN-716543
 * String definitions
 *
 * @package    auth_dq
 * @author     Ken Chang <kenc@pukunui.com>, Pukunui Technology
 * @copyright  2018 onwards, Pukunui
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

$string['db:nocourse'] = 'This course does not exists';
$string['enroluser:h1:enrolmentstatus'] = 'Enrolment Status';
$string['enroluser:metatag:heading'] = 'Enrolment Status';
$string['enrolment:admin:subject'] = '{$a->firstname} {$a->lastname} has enrolled in {$a->coursefullname}';
$string['enrolment:admin:message'] = 'The email is to inform you that {$a->firstname} {$a->lastname} has
enrolled into the following course: {$a->coursefullname}

To access the course click on the link below

{$a->url}

Please do not reply to this email.';
$string['enrolment:user:subject'] = 'Enrolled in: {$a->coursefullname}';
$string['enrolment:user:message'] = 'The email is to inform you that you have been enrolled into the
following course: {$a->coursefullname}

Your login details are:

Username: {$a->username}
Password: {$a->password}

To access the course click on the link below

{$a->url}

Please do not reply to this email.

Site Admin
{$a->supportname}
{$a->supportemail}';
$string['pluginname'] = 'DQ Authentication';
$string['setting:lasttimestamp'] = 'Last time user enrolled';
$string['setting:lasttimestamp:desc'] = 'This setting controls the availability of /auth/dq/dquser.php.
Please format your timestamp to DD-MM-YYYY HH:MM:SS.
Otherwise this process will not  be executed by system. 
If the timestamp in the request is older than last time user enrolled, the process will stop.';
$string['user:confirm:fail'] = 'User confirmation has failed';