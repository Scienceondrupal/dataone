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
