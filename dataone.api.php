<?php

/**
 * @file
 * dataone.api.php
 */

/**
 * Provide for implementing module to define version-specific information.
 *
 * Describe what should/can be altered.
 *
 * @see dataone.module
 *
 * @param array $versions
 *   A structured array suitable for drupal_render(). Passed by reference.
 */
function hook_dataone_api_versions_alter(&$versions) {

  // Implementing modules should use this hook to define their own API classes.
  $versions['v1']['class'] = 'MyModuleDataOneApiVersionOne';
}

/**
 * Provide for an implementing module to act on DataONE API events.
 *
 * The most notable event to occur is a replication event which should be logged
 * per the documentation. These events could be reported from the calls to
 * getLogRecords() in version 1 of the API.
 *
 * @see DataOneApi::getDataOneEventTypes()
 *
 * @param string $event_type
 *   The event that just occurred.
 *
 * @param mixed $pid
 *   Either the string identifier or FALSE
 */
function hook_dataone_event($event_type, $pid = FALSE) {
  $vars = array('@event' => $event_type, '@pid' => $pid);
  watchdog('dataone', '@event occurred on object @pid', $vars, WATCHDOG_INFO);
}
