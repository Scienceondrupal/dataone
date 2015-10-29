<?php

/**
 * @file
 * DataOneApiVersionOne.php
 */

class DataOneApiVersionOne extends DataOneApi {

  /**
   * Get information about the API paths.
   *
   * Q: Why is the method name the key of the array?
   * A: At first, we tried using the path as the key, but ran into two issues:
   *    1) The same API function can have multiple paths which would duplicate
   *       information and not be obvious that both need to be the same. A
   *       tight coupling makes this easier to manage.
   *       @see MNCore.getCapabilities()
   *    2) One of the paths defined by the API is '/' which as a menu path would
   *       be the endpoint path + '' (empty string). The empty string isn't an
   *       ideal key for an associative array.
   *       @see MNCore.getCapabilities()
   *
   * @param array
   *   Associative array keyed by API method relative to the version endpoint
   */
  static public function getApiMenuPaths() {
    return array(
      'MNCore.ping()' => array(
        'paths' => array('/monitor/ping'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'ping',
      ),
      'MNCore.getLogRecords()' => array(
        'paths' => array('/log'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getLogRecords',
        'query_parameters' => array(
          'fromDate' => array('required' => FALSE),
          'toDate' => array('required' => FALSE),
          'event' => array('required' => FALSE),
          'pidFilter' => array('required' => FALSE),
          'start' => array('required' => FALSE, 'default_value' => 0),
          'count' => array('required' => FALSE, 'default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_LOG_COUNT, DATAONE_DEFAULT_MAX_LOG_RECORDS)),
        ),
      ),
      'MNCore.getCapabilities()' => array(
        'paths' => array('', '/node'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getCapabilities',
      ),
      'MNRead.getSystemMetadata()' => array(
        'paths' => array('/meta/%dataone_api_v1_pid'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getSystemMetadata',
        'arguments' => array(1 => 'pid'),
      ),
      'MNRead.describe()' => array(
        'paths' => array('/object/%dataone_api_v1_pid'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'describe',
        'arguments' => array(1 => 'pid'),
      ),
      'MNRead.getChecksum()' => array(
        'paths' => array('/checksum/%dataone_api_v1_pid'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getChecksum',
        'arguments' => array(1 => 'pid'),
        'query_parameters' => array(
          'checksumAlgorithm' => array('required' => FALSE),
        ),
      ),
      'MNRead.listObjects()' => array(
        'paths' => array('/object'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'listObjects',
        'query_parameters' => array(
          'fromDate' => array('required' => FALSE),
          'toDate' => array('required' => FALSE),
          'formatId' => array('required' => FALSE),
          'replicaStatus' => array('required' => FALSE),
          'start' => array('required' => FALSE, 'default_value' => 0),
          'count' => array('required' => FALSE, 'default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_OBJECT_COUNT, DATAONE_DEFAULT_MAX_OBJECT_RECORDS)),
        ),
      ),
      'MNRead.synchronizationFailed()' => array(
        'paths' => array('/error'),
        'method' => 'POST',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'synchronizationFailed',
        'query_parameters' => array(
          'message' => array('required' => TRUE),
        ),
      ),
      'MNRead.getReplica()' => array(
        'paths' => array('/replica/%dataone_api_v1_pid'),
        'method' => 'GET',
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getReplica',
      ),
    );
  }

  /**
   * Get Path information for a path.
   *
   * Because a path isn't the key of the getApiMenuPaths() array, we must lookup
   * that path inside the array.
   *
   * @param string $path
   *   The path to lookup
   *
   * @return array
   *   The menu path information related to the given path
   */
  static private function getPathInformation($path) {
    $paths = DataOneApiVersionOne::getApiMenuPaths();
    if (!empty($paths)) {
      foreach ($paths as $title => $info) {
        if (in_array($path, $info['paths'])) {
          return $info;
        }
      }
    }

    return FALSE;
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

    // X.509 certificate information.
    $session = DataOneApi::getSession();

    // Check access control...

    return TRUE;
  }

  /**
   * Handle a request.
   *
   * @param array $args
   *   Any arguments from the request
   */
  static public function requestHandler($args) {

    // Figure out which path was called.
    $full_path = current_path();
    $endpoint_path = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_ENDPOINT);
    $api_path = substr($full_path, strlen($endpoint_path));

    // Figure out which function to call.
    $path_info = DataOneApiVersionOne::getPathInformation($api_path);
    $function = $path_info['function'];

    // Call the function.
    return DataOneApiVersionOne::$function($args);
  }

  /**
   * Get a Pid.
   */
  static public function getPid($pid) {
    //throw some exception in this implementation.
  }

  /**
   * Implements DataONE MNCore.ping().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.ping
   *
   * Possible exceptions:
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2041, 'In development');
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2042, 'Failed');
   *
   * Insufficient Resources
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InsufficientResources
   * @example DataOneApiVersionOne::throwInsufficientResources(2045, 'Overloaded');
   */
  static public function ping() {
    // The response to send the client.
    $response = FALSE;

    try {

      // Is the API live?
      $status = _dataone_get_variable_name($version, DATAONE_VARIABLE_API_STATUS);
      switch ($status) {
        case DATAONE_API_STATUS_PRODUCTION:
          // Valid API body is the empty string.
          $response = '';
          break;

        case DATAONE_API_STATUS_DEVELOPMENT:
          DataOneApiVersionOne::throwNotImplemented(2041, 'In development');
          break;

        case DATAONE_API_STATUS_OFF:
        default:
          DataOneApiVersionOne::throwNotImplemented(2041, 'The API is unavailable at this time.');
      }

    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
    }

    // Send the response. The API says no body on successul, valid ping().
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.getLogRecords().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getLogRecords
   */
  static public function getLogRecords() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.getCapabilities().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getCapabilities
   */
  static public function getCapabilities() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.get().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.get
   */
  static public function get() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.getSystemMetadata().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getSystemMetadata
   */
  static public function getSystemMetadata() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.describe().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.describe
   */
  static public function describe() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.getChecksum().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getChecksum
   */
  static public function getChecksum() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.listObjects().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.listObjects
   */
  static public function listObjects() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.synchronizationFailed().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.synchronizationFailed
   */
  static public function synchronizationFailed() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Implements DataONE MNCore.getReplica().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getReplica
   */
  static public function getReplica() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response);
  }

  /**
   * Generate DataONE API response.
   *
   * @param DOMDocument $response
   *   The XML to send the client
   */
  static public function sendResponse($response) {

    // Set the Content-Type, API ver. 1 defines it to always be XML.
    drupal_add_http_header('Content-Type', 'application/xml');

    // Send the XML.
    if ($response instanceof DOMDocument) {
      print $response->saveXML();
    }
    else {
      print $response;
    }

    // Quit processing of the request.
    drupal_exit();
  }

  /**
   * Throw AuthenticationTimeout Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwAuthenticationTimeout($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('AuthenticationTimeout', 408, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw IdentifierNotUnique Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwIdentifierNotUnique($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('IdentifierNotUnique', 409, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InsufficientResources Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInsufficientResources($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('InsufficientResources', 413, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidCredentials Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidCredentials($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('InvalidCredentials', 401, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidRequest Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidRequest($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('InvalidRequest', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidSystemMetadata Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidSystemMetadata($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('InvalidSystemMetadata', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidToken Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidToken($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('InvalidToken', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw NotAuthorized Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotAuthorized($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotAuthorized', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw NotFound Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotFound($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotFound', 404, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw NotImplemented Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotImplemented($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotImplemented', 501, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw ServiceFailure Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwServiceFailure($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('ServiceFailure', 500, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw UnsupportedMetadataType Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwUnsupportedMetadataType($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('UnsupportedMetadataType', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw UnsupportedType Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwUnsupportedType($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('UnsupportedType', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw VersionMismatch Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwVersionMismatch($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('VersionMismatch', 409, $detail_code, $message, $trace_info, $watchdog_code);
  }
}
