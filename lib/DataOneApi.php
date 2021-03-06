<?php

/**
 * @file
 * DataOneApi.php
 */

/**
 * An abtract implementation of a DataONE API.
 */
abstract class DataOneApi {

  /**
   * Get the possible values for a DataONE Event type.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Event
   *
   * @return array
   *   The event types as strings
   */
  static public function getDataOneEventTypes() {
    return array(
      'create',
      'read',
      'update',
      'delete',
      'replicate',
      'synchronization_failed',
      'replication_failed',
    );
  }

  /**
   * Get the endpoint base URL of this Member Node.
   *
   * @param string $version
   *   The version of the DataONE API
   *
   * @return string
   *   The Member Node base URL
   */
  static public function getBaseURL($version) {
    $url = dataone_get_member_node_endpoint($version, TRUE);
    // Strip off the version.
    $end = '/' . $version;
    $pos = strpos($url, $end);
    // What's left is the baseURL.
    return substr($url, 0, $pos);
  }

  /**
   * Get information about the API paths.
   *
   * @return array
   *   Associative array keyed by API method relative to the version endpoint
   */
  static public function getApiMenuPaths(){
    watchdog('dataone', 'call to getApiMenuPaths() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return array();
  }

  /**
   * Access control for a request.
   *
   * @param array $args
   *   Any arguments from the request
   *
   * @return BOOL
   */
  static public function accessControl($args) {
    watchdog('dataone', 'call to accessControl() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return TRUE;
  }

  /**
   * Handle a request.
   *
   * @param array $args
   *   Any arguments from the request
   */
  public function requestHandler($args) {
    watchdog('dataone', 'call to requestHandler() should be made by an implementing class', array(), WATCHDOG_ERROR);
  }
}
