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

    /**
   * Generate DataONE API response.
   *
   * @param string $response
   *   The string to send the client
   *
   * @param mixed $error_code
   *   The ServiceFailure exception detail code for the calling function
   *
   * @param string $content_type
   *   The content type header value.
   *   Most all services of API ver. 1 are XML
   */
  static public function sendResponse($response, $error_code = FALSE, $content_type = 'application/xml') {
    watchdog('dataone', 'call to sendResponse() should be made by an implementing class', array(), WATCHDOG_ERROR);
  }
}
