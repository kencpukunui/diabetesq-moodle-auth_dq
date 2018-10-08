<?php
/**
 * Custom authentication for Diabetes Qualified project
 *
 * Administration settings
 *
 * @package    auth_dq
 * @author     Ken Chang <kenc@pukunui.com>, Pukunui
 * @copyright  2018 onwards, Pukunui
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

$settings->add(new admin_setting_configtext(
    'auth_dq/lasttimestamptodate',
    new lang_string('setting:lasttimestamp', 'auth_dq'),
    new lang_string('setting:lasttimestamp:desc', 'auth_dq'),
    0,
    PARAM_TEXT,
    20
    ));
