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
