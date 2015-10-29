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
   * @param array
   *   Associative array keyed by API method relative to the version endpoint
   */
  static public function getApiMenuPaths(){
    return NULL;
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
  static public function sendResponse($response) {

  }

  /**
   * Get the X.509 Certificate data.
   */
  static public function getSession() {
    $cert = !empty($_SERVER['SSL_CLIENT_CERT']) ? $_SERVER['SSL_CLIENT_CERT'] : FALSE;
    return (!empty($cert)) ? openssl_x509_parse($cert) : FALSE;
  }
}
