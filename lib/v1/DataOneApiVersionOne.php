<?php

/**
 * @file
 * DataOneApiVersionOne.php
 *
 * FUNCTIONS TO OVERRIDE:
 *
 * getPid()
 * checkSession()
 * ping()
 * getLogRecords()
 * getCapabilities()
 * get()
 * getSystemMetadata()
 * describe()
 * getChecksum()
 * listObjects()
 * synchronizationFailed()
 * getReplica()
 */

class DataOneApiVersionOne extends DataOneApi {

  /**
   * Get a representation for a given PID.
   *
   * This function should be public so that it can be called by the menu loader.
   * This function is static so that it can be called by
   * dataone_api_v1_pid_load().
   * @see dataone_api_v1_pid_load
   *
   * @param string $pid
   *   The PID from the request.
   *
   * @param mixed
   *   Either FALSE or a structure like a node or entity or array.
   */
  static public function getPid($pid) {
    watchdog('dataone', 'call to getPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return FALSE;
  }

  /**
  * Make sure a session is authorized for a certain request.
  *
  * This function is protected and not static so that it can be overridden by
  * an extending class.
  *
  * @param integer $invalid_token_code
  *   The detail code for throwing InvalidToken Exception
  *
  * @param integer $not_authorized_code
  *   The detail code for throwing NotAuthorized Exception
  */
  protected function checkSession($invalid_token_code, $not_authorized_code) {
    // Check authentication.
    $session = $this->getSession();
    // If no session information, then throw Invalid Token.
    if (empty($session)) {
      DataOneApiVersionOne::throwInvalidToken($invalid_token_code, 'No authentication information provided');
    }

    // An implementing class should decide if the session is not authorized and
    // call DataOneApiVersionOne::throwNotAuthorized($not_authorized_code, 'Some message');
  }

  /**
   * Implements DataONE MNCore.ping().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.ping
   *
   * Possible exceptions:
   *
   * Not Implemented
   *   Ping is a required operation and so an operational member node should
   *   never return this exception unless under development.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2041, 'The API implementation is in development');
   *
   * Service Failure
   *   A ServiceFailure exception indicates that the node is not currently
   *   operational as a member node. A coordinating node or monitoring service
   *   may use this as an indication that the member node should be taken out of
   *   the pool of active nodes, though ping should be called on a regular basis
   *   to determine when the node might b ready to resume normal operations.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2042, 'Offline');
   *
   * Insufficient Resources
   *    A ping response may return InsufficientResources if for example the
   *    system is in a state where normal DataONE operations may be impeded
   *    by an unusually high load on the node.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InsufficientResources
   * @example DataOneApiVersionOne::throwInsufficientResources(2045, 'Overloaded');
   */
  protected function ping() {
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.ping().
      $this->checkOnlineStatus(2041, 2042);
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      DataOneApiVersionOne::sendResponse($response, 2042);
    }

    // Send the response.
    // The API says no body as 'text/plain' on successul, valid ping().
    DataOneApiVersionOne::sendResponse('', 2042, 'text/plain');
  }

  /**
   * Implements DataONE MNCore.getLogRecords().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getLogRecords
   *
   * Possible exceptions:
   *
   * Not Authorized
   *    Raised if the user making the request is not authorized to access the
   *    log records. This is determined by the policy of the Member Node.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(1460, 'Not Authorized');
   *
   * Invalid Request
   *    The request parameters were malformed or an invalid date range was
   *    specified.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidRequest
   * @example DataOneApiVersionOne::throwInvalidRequest(1480, 'Invalid Request');
   *
   * Service Failure
   *   Some sort of system failure occurred that is preventing the requested
   *   operation from completing successfully. This error can be raised by any
   *   method in the DataONE API.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1490, 'Failed');
   *
   * Invalid Token
   *   The supplied authentication token (Session) could not be verified as
   *   being valid.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1470, 'Could not authenticate the session');
   *
   * Not Implemented
   *   A method is not implemented, or alternatively, features of a particular
   *   method are not implemented.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1461, 'The API implementation is in development');
   */
  protected function getLogRecords() {
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.getLogRecords().
      $this->checkOnlineStatus(1461, 1490);

      // Information about current path.
      $path_info = $this->getPathConfig();

      // Validate the session.
      // Pass the InvalidToken detail code specific to MNCore.getLogRecords().
      $this->checkSession(1470, 1460, $path_info);

      // Check the query parameters.
      $raw_params = drupal_get_query_parameters();
      $parameters = $this->checkQueryParameters($path_info, $raw_params);

      // The response to send the client.
      $response = FALSE;

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(1461, 'getLogRecords() has not been implemented yet.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 1490);
  }

  /**
   * Implements DataONE MNCore.getCapabilities().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getCapabilities
   *
   * Possible exceptions:
   *
   * Service Failure
   *   Some sort of system failure occurred that is preventing the requested
   *   operation from completing successfully. This error can be raised by any
   *   method in the DataONE API.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2162, 'Failed');
   *
   * Not Implemented
   *   A method is not implemented, or alternatively, features of a particular
   *   method are not implemented.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2160, 'The API implementation is in development');
   */
  protected function getCapabilities() {

    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.getLogRecords().
      $this->checkOnlineStatus(1461, 1490);

      // Implementation should do something here.
      $replicate = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_REPLICATE, DATAONE_API_FALSE_STRING);
      $synchronize = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNCHRONIZE, DATAONE_API_FALSE_STRING);
      $sync_hour = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_HOUR, '*');
      $sync_mday = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MDAY, '*');
      $sync_min = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MIN, '*');
      $sync_mon = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MON, '*');
      $sync_sec = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_SEC, '*');
      $sync_wday = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_WDAY, '*');
      $sync_year = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_YEAR, '*');
      $status = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_STATUS);
      $state = (DATAONE_API_STATUS_PRODUCTION == $status) ? "up" : "down";
      $available = (DATAONE_API_STATUS_PRODUCTION == $status) ? DATAONE_API_TRUE_STRING : DATAONE_API_FALSE_STRING;
      $ping = DATAONE_API_TRUE_STRING;
      try {
        // Check that the API is live and accessible.
        // Passing the NotImplemented and ServiceFailure exception detail codes
        // specific to MNCore.ping().
        $this->checkOnlineStatus(2160, 2162);
      }
      catch (DataOneApiVersionOneException $exc) {
        // If an Exception is thrown ping() is false.
        $ping = DATAONE_API_FALSE_STRING;
      }
      $response = DataOneApiVersionOne::generateXmlWriter();
      $elements = array(
        'd1:node' => array(
          '_keys' => array(
            'subject' => '_subject_',
          ),
          '_attrs' => array(
            'xmlns:d1' => 'http://ns.dataone.org/service/types/v1',
            'replicate' => $replicate,
            'synchronize' => $synchronize,
            'type' => 'mn',
            'state' => $state,
          ),
          'identifier' => _dataone_get_member_node_identifier(TRUE),
          'name' => _dataone_get_member_node_name(),
          'description' => _dataone_get_member_node_description(),
          'baseURL' => _dataone_get_member_node_endpoint(TRUE),
          'services' => array(
            '_keys' => array('service' => '_service'),
            '_service0' => array(
              '_attrs' => array(
                'name' => 'MNRead',
                'version' => DATAONE_API_VERSION_1,
                'available' => $available,
              ),
            ),
            '_service1' => array(
              '_attrs' => array(
                'name' => 'MNCore',
                'version' => DATAONE_API_VERSION_1,
                'available' => $available,
              ),
            ),
          ),
          'synchronization' => array(
            'schedule' => array(
              '_attrs' => array(
                'hour' => $sync_hour,
                'mday' => $sync_mday,
                'min' => $sync_min,
                'mon' => $sync_mon,
                'sec' => $sync_sec,
                'wday' => $sync_wday,
                'year' => $sync_year,
              ),
            ),
          ),
          'ping' => array(
            '_attrs' => array('success' => $ping),
          ),
          '_subject_0' => '',
          'contactSubject' => variable_get(DATAONE_API_CONTACT_SUBJECT),
        ),
      );

      $subjects = _dataone_get_member_node_subjects(TRUE);
      foreach ($subjects as $idx => $subject) {
        $elements['d1:node']['_subject_' . $idx] = $subject;
      }

      $xml = $this->generateXmlWriter();
      $this->addXmlWriterElements($xml, $elements);
      $response = $this->printXmlWriter($xml);
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 2162);
  }

  /**
   * Implements DataONE MNCore.get().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.get
   */
  protected function get() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 1030);
  }

  /**
   * Implements DataONE MNCore.getSystemMetadata().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getSystemMetadata
   */
  protected function getSystemMetadata() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 1090);
  }

  /**
   * Implements DataONE MNCore.describe().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.describe
   */
  protected function describe() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 1390);
  }

  /**
   * Implements DataONE MNCore.getChecksum().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getChecksum
   */
  protected function getChecksum() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 1410);
  }

  /**
   * Implements DataONE MNCore.listObjects().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.listObjects
   */
  protected function listObjects() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 1580);
  }

  /**
   * Implements DataONE MNCore.synchronizationFailed().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.synchronizationFailed
   */
  protected function synchronizationFailed() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 2161);
  }

  /**
   * Implements DataONE MNCore.getReplica().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getReplica
   */
  protected function getReplica() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Do something.
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    // Send the response.
    DataOneApiVersionOne::sendResponse($response, 2181);
  }

  /*** END of FUNCTIONS TO OVERRIDE ***/

  /*** CLASS PROPERTIES ***/
  // The portion of the getApiMenuPaths() array related to the current request.
  protected $path_config;

  /**
   * Build a request handler for the current API request.
   *
   * @param array $path_config
   *   The path configuration from getApiMenuPaths().
   */
  public function __construct(array $path_config) {
    // Set the path configuration.
    $this->path_config = $path_config;
  }

  /**
   * Build a request handler for the current API request.
   *
   * @return object
   *   A DataOneApiVersionOne implementation class
   */
  static public function construct() {

    // Figure out which path was called.
    $full_path = current_path();
    $endpoint_path = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_ENDPOINT);
    $api_path = substr($full_path, strlen($endpoint_path));

    // Set the path configuration.
    $instance = new self(DataOneApiVersionOne::getPathInformation($api_path));
    return $instance;
  }

  /**
   * Build a request handler for the current API request.
   *
   * @param string $path
   *   The relative path of the API.
   *
   * @return object
   *   A DataOneApiVersionOne implementation class
   */
  static public function constructWithPath(string $path) {
    // Find and set the path configuration.
    $instance = new self(DataOneApiVersionOne::getPathInformation($path));
    return $instance;
  }

  /**
   * Get the path configuration for a request.
   */
  public function getPathConfig() {
    return $this->path_config;
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
    // Ver. 1 handles access control with Exception handling
    // with specific detail codes based on the requested service.
    // Return TRUE to allow the service to specify access control.
    return TRUE;
  }

  /**
   * Handle a request.
   *
   * @param array $args
   *   Any arguments from the request
   */
  public function requestHandler($args) {

    // Call the related function.
    $function = $this->getRequestedFunction();
    $this->$function($args);
  }

  /**
   * Get the function assigned to the current request.
   */
  protected function getRequestedFunction() {
    $cfg = $this->getPathConfig();
    return $cfg['function'];
  }

  /**
   * Make sure the API is online.
   *
   * This function is protected and not static so that it can be overridden by
   * an extending class.
   *
   * @param integer $not_implemented_code
   *   The detail code for throwing NoImplemented Exception
   *
   * @param integer $service_failure_code
   *   The detail code for throwing ServiceFailure Exception
   */
  protected function checkOnlineStatus($not_implemented_code, $service_failure_code) {
    // Is the API live?
    $status = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_STATUS);
    switch ($status) {
      case DATAONE_API_STATUS_PRODUCTION:
        break;

      case DATAONE_API_STATUS_DEVELOPMENT:
        DataOneApiVersionOne::throwNotImplemented($not_implemented_code, 'The API implementation is in development');
        break;

      case DATAONE_API_STATUS_OFF:
      default:
        DataOneApiVersionOne::throwServiceFailure($service_failure_code, 'The API has been turned offline. Please try again later.');
    }
  }

  /**
   * Get the X.509 Certificate data.
   *
   * @return array
   *   The session authentication data for a request
   */
  protected function getSession() {
    $cert = !empty($_SERVER['SSL_CLIENT_CERT']) ? $_SERVER['SSL_CLIENT_CERT'] : FALSE;
    return (!empty($cert)) ? openssl_x509_parse($cert) : FALSE;
  }

  /**
   * Check for Invalid parameters for a request.
   *
   * @param array $path_info
   *   The information about the path of the current request
   *
   * @param array $parameters
   *   an array of query parameters from drupal_get_query_parameters()
   *
   * @return array
   *   Processed parameter values formatted like drupal_get_query_parameters()
   *   except that single values are formatted as an array of one value.
   */
  protected function checkQueryParameters($path_info, $parameters) {
    // Check for required or invalid parameters.
    foreach ($path_info['query_parameters'] as $query_param => $parameter_info) {
      // Any missing required parameters?
      if (TRUE == $parameter_info['required'] && empty($parameters[$query_param])) {
        DataOneApiVersionOne::throwInvalidRequest(1480, 'Required parameter "$query_param" is missing.');
      }
    }

    // The processed parameters and values.
    $processed_parameters = array();

    // Check for invalid parameter values.
    if (!empty($parameters)) {
      foreach ($parameters as $parameter => $value) {
        // Check for cardinality constraints.
        $min_card = !empty($path_info['query_parameters'][$parameter]['min_cardinality']) ? $path_info['query_parameters'][$parameter]['min_cardinality'] : FALSE;
        $max_card = !empty($path_info['query_parameters'][$parameter]['max_cardinality']) ? $path_info['query_parameters'][$parameter]['max_cardinality'] : FALSE;
        if ($min_card || $max_card) {
          $count = count($value);
          // Maximum cardinality.
          if ($max_card && ($count > $max_card)) {
            $msg_params = array('!param' => $parameter, '@max' => $max_card, '@count' => $count);
            $msg = t('The maximum cardinality of parameter "!param" is @max, but received @count', $msg_params);
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            DataOneApiVersionOne::throwInvalidToken(1480, $msg, $trace_info);
          }
          // Minimum cardinality.
          elseif ($min_card && ($max_count < $min_card)) {
            $msg_params = array('!param' => $parameter, '@min' => $min_card, '@count' => $count);
            $msg = t('The minimum cardinality of parameter "!param" is @min, but received @count', $msg_params);
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            DataOneApiVersionOne::throwInvalidToken(1480, $msg, $trace_info);
          }
        }

        // Process and format the parameter value(s).
        if (!empty($path_info['query_parameters'][$parameter])) {
          $param_info = $path_info['query_parameters'][$parameter];
          $array_value = is_array($value) ? $value : array($value);
          $processed_parameters[$parameter] = $this->processRequestParameter($parameter, $param_info, $array_value, 1480);
        }
        else {
          // Ignore unknown parameters.
          continue;
        }
      }
    }

    return $processed_parameters;
  }

  /**
   * Process a parameter's value.
   *
   * @param string $parameter
   *   The name of the parameter
   *
   * @param array $parameter_info
   *   The configuration info for the specified parameter in getApiMenuPaths().
   *
   * @param mixed $value
   *   The value of the parameter from drupal_get_query_parameters().
   *
   * @param integer $invalid_request_code
   *   The InvalidRequest detail code specific to the calling function
   *
   * @return mixed
   *   The processed value for use by the calling function
   */
  protected function processRequestParameter($parameter, $parameter_info, $value, $invalid_request_code) {
    // Check the data type.
    if (!empty($parameter_info['type'])) {
      switch ($parameter_info['type']) {
        case 'date':
          $date = strtotime($value);
          if (!$date) {
            // Trace info for any possible exceptions.
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            $msg = t('!param must be a date.', array('!param' => $parameter));
            DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
          }
          break;

        case 'integer':
          if ($value !== '' && (!is_numeric($value) || intval($value) != $value)) {
            // Trace info for any possible exceptions.
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            $msg = t('!param must be an integer.', array('!param' => $parameter));
            DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
          }
          break;
      }
    }

    return $value;
  }

  /**
   * Get the trace information for a request parameter.
   *
   * @param mixed $parameter_value
   *   The value of a request parameter
   *
   * @return array
   *   A keyed array for insertion into the trace information array
   */
  static public function getTraceInformationForRequestParameter($parameter_value) {
    // Trace info for any possible exceptions.
    $trace_value = '';
    if (is_array($parameter_value)) {
      $last = last($parameter_value);
      foreach ($parameter_value as $k => $v) {
        $trace_value .= $v;
        if ($last != $v) {
          $trace_value .= ', ';
        }
      }
    }
    else {
      $trace_value = $value;
    }
    return array($parameter => htmlspecialchars($trace_value, ENT_XML1));
  }

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
          'fromDate' => array(
            'required' => FALSE,
            'type' => 'date',
            'max_cardinality' => 1,
          ),
          'toDate' => array(
            'required' => FALSE,
            'type' => 'date',
            'max_cardinality' => 1,
          ),
          'event' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
          ),
          'pidFilter' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
          ),
          'start' => array(
            'required' => FALSE,
            'type' => 'integer',
            'default_value' => 0,
            'max_cardinality' => 1,
          ),
          'count' => array(
            'required' => FALSE,
            'type' => 'integer',
            'default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_LOG_COUNT, DATAONE_DEFAULT_MAX_LOG_RECORDS),
            'max_cardinality' => 1,
          ),
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
  static public function getPathInformation($path) {
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
   * Generate DataONE API response.
   *
   * @param string $response
   *   The string to send the client
   *
   * @param integer $error_code
   *   The ServiceFailure exception detail code for the calling function
   *
   * @param string $content_type
   *   The content type header value.
   *   Most all services of API ver. 1 are XML
   */
  static public function sendResponse($response, $error_code = FALSE, $content_type = 'application/xml') {
    // Send the response.
    if (is_string($response)) {
      print $response;
    }
    elseif ($error_code) {
      $msg = t('Unknown error occurred with response: !resp', array('!resp' => $response));
      try {
        DataOneApiVersionOne::throwServiceFailure($error_code, $msg);
      } catch(Exception $exc) {
        watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
        print $exc->generateErrorResponse();
      }
    }
    else {
      drupal_add_http_header('Status', 500);
      print 'Unknown error occurred without a service failure code.';
      $content_type = 'text/plain';
    }

    // Set the Content-Type.
    drupal_add_http_header('Content-Type', $content_type);

    // Quit processing of the request.
    drupal_exit();
  }

  /**
   * Start an XMLWriter. Provide a stub for possible override.
   * @see DataOneApiXml::generateXmlWriter()
   *
   * @param BOOL $indent
   *   Should the Writer format the output
   *
   * @return XMLWriter
   *   The generated XMLWriter
   */
  static public function generateXmlWriter($indent = TRUE) {
    return DataOneApiXml::generateXmlWriter($indent);
  }

  /**
   * Add elements to an XMLWriter. Provide a stub for possible override.
   * @see DataOneApiXml::addXmlWriterElements()
   *
   * @param XMLWriter $xml
   *   The XMLWriter to modify
   *
   * @param array $elements
   *   The elements to add
   */
  static public function addXmlWriterElements($xml, $elements) {
    DataOneApiXml::addXmlWriterElements($xml, $elements);
  }

  /**
   * Print the XML. Provide a stub for possible override.
   * @see DataOneApiXml::printXmlWriter()
   *
   * @param XMLWriter $xml
   *   The XMLWriter to print
   *
   * @param BOOL $end_root_element
   *   Should the root XML element be closed?
   *
   * @return string
   *   The XML as a string
   */
  static public function printXmlWriter($xml, $end_root_element = TRUE) {
    return DataOneApiXml::printXmlWriter($xml, $end_root_element);
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
