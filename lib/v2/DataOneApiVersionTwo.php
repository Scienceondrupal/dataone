<?php

/**
 * @file
 * DataOneApiVersionOne.php
 */

class DataOneApiVersionTwo extends DataOneApi {

  /**
   * Get information about the API paths.
   *
   * @param array
   *   Associative array keyed by API method relative to the version endpoint
   */
  static public function getApiMenuPaths(){
    return $parent::getApiMenuPaths();
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
    return FALSE;
  }

  /**
   * Handle a request.
   *
   * @param array $args
   *   Any arguments from the request
   */
  static public function requestHandler($args) {

  }

  /**
   * Given some response, send it to the client.
   */
  public function sendResponse($response){

  }
}
